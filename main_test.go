package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jratienza65/railbird/internal/config"
	"github.com/jratienza65/railbird/internal/netbird"
)

func baseRuntimeDependencies() runtimeDependencies {
	return runtimeDependencies{
		requireRuntimeIdentity: func(int, int) error { return nil },
		prepareBootstrap: func(_ string, _, _ int, classify func() error) error {
			return classify()
		},
		classifyBootstrap:     func(string, int, int) error { return nil },
		prepareEphemeralState: func(string, int, int) error { return nil },
		loadPersistentIdentity: func(string, string, int, int) (netbird.PersistentIdentity, error) {
			return netbird.PersistentIdentity{PrivateKey: "private", PublicKey: "public"}, nil
		},
		runBootstrap:    func(context.Context, config.Config) (string, error) { return "public-key", nil },
		runServing:      func(context.Context, config.Config, netbird.Options) error { return nil },
		bootstrapOutput: &bytes.Buffer{},
	}
}

func mapEnvironment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func testEgressEnvironment() map[string]string {
	return map[string]string{
		"MODE":                  "egress",
		"FORWARDS":              "5432=127.0.0.1:5432",
		"NB_MANAGEMENT_URL":     "https://mgmt.example.com",
		"NB_SETUP_KEY":          "secret-setup-key",
		"RAILWAY_DEPLOYMENT_ID": "deployment-a",
	}
}

func testBootstrapEnvironment(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"MODE":                      "ingress",
		"NB_MANAGEMENT_URL":         "https://mgmt.example.com",
		"NB_SETUP_KEY":              "secret-setup-key",
		"NB_IDENTITY_MODE":          "bootstrap",
		"RAILWAY_SERVICE_ID":        "service-a",
		"RAILWAY_VOLUME_MOUNT_PATH": t.TempDir(),
		"RAILWAY_RUN_UID":           "0",
	}
}

func TestRunEgressUsesEphemeralCredentialAndServingSupervisor(t *testing.T) {
	deps := baseRuntimeDependencies()
	var prepared string
	var gotOptions netbird.Options
	deps.prepareEphemeralState = func(path string, uid, gid int) error {
		prepared = path
		if uid != runtimeUID || gid != runtimeGID {
			t.Fatalf("runtime identity = %d:%d", uid, gid)
		}
		return nil
	}
	deps.runServing = func(_ context.Context, cfg config.Config, opts netbird.Options) error {
		if cfg.Mode != config.ModeEgress {
			t.Fatalf("mode = %s", cfg.Mode)
		}
		gotOptions = opts
		return nil
	}

	if err := run(context.Background(), nil, mapEnvironment(testEgressEnvironment()), deps); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if prepared != "/var/lib/railbird/netbird" || gotOptions.SetupKey != "secret-setup-key" || gotOptions.PrivateKey != "" || gotOptions.Mode != config.ModeEgress {
		t.Fatalf("prepared=%q options=%+v", prepared, gotOptions)
	}
}

func TestRunPersistentValidatesVolumeBeforeServing(t *testing.T) {
	root := t.TempDir()
	env := map[string]string{
		"MODE":                        "ingress",
		"FORWARDS":                    "3000=127.0.0.1:3000",
		"NB_MANAGEMENT_URL":           "https://mgmt.example.com",
		"NB_IDENTITY_MODE":            "persistent",
		"NB_EXPECTED_PEER_PUBLIC_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"RAILWAY_SERVICE_ID":          "service-a",
		"RAILWAY_VOLUME_MOUNT_PATH":   root,
	}
	deps := baseRuntimeDependencies()
	validated := false
	deps.loadPersistentIdentity = func(gotRoot, expected string, uid, gid int) (netbird.PersistentIdentity, error) {
		validated = true
		if gotRoot != root || expected != env["NB_EXPECTED_PEER_PUBLIC_KEY"] || uid != runtimeUID || gid != runtimeGID {
			t.Fatalf("validation inputs root=%q expected=%q ids=%d:%d", gotRoot, expected, uid, gid)
		}
		return netbird.PersistentIdentity{PrivateKey: "validated-private", PublicKey: expected}, nil
	}
	deps.runServing = func(_ context.Context, _ config.Config, opts netbird.Options) error {
		if !validated || opts.PrivateKey != "validated-private" || opts.SetupKey != "" {
			t.Fatalf("serving before validation or bad options: validated=%v opts=%+v", validated, opts)
		}
		return nil
	}

	if err := run(context.Background(), nil, mapEnvironment(env), deps); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunBootstrapClassifiesDropsAndNeverServes(t *testing.T) {
	env := testBootstrapEnvironment(t)
	deps := baseRuntimeDependencies()
	events := []string{}
	output := &bytes.Buffer{}
	deps.bootstrapOutput = output
	deps.classifyBootstrap = func(root string, uid, gid int) error {
		events = append(events, "classify")
		if root != env["RAILWAY_VOLUME_MOUNT_PATH"] || uid != runtimeUID || gid != runtimeGID {
			t.Fatalf("classifier inputs root=%q ids=%d:%d", root, uid, gid)
		}
		return nil
	}
	deps.prepareBootstrap = func(_ string, _, _ int, classify func() error) error {
		if err := classify(); err != nil {
			return err
		}
		events = append(events, "drop")
		return nil
	}
	deps.runBootstrap = func(context.Context, config.Config) (string, error) {
		events = append(events, "bootstrap")
		return "expected-public-key", nil
	}
	deps.runServing = func(context.Context, config.Config, netbird.Options) error {
		t.Fatal("bootstrap entered serving supervisor")
		return nil
	}

	if err := run(context.Background(), nil, mapEnvironment(env), deps); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if strings.Join(events, ",") != "classify,drop,bootstrap" {
		t.Fatalf("events = %v", events)
	}
	if output.String() != "RAILBIRD_PEER_PUBLIC_KEY=expected-public-key\n" {
		t.Fatalf("bootstrap output = %q", output.String())
	}
}

func TestRunStopsBeforeServingOnPrivilegeOrIdentityFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*runtimeDependencies)
	}{
		{name: "serving identity", edit: func(deps *runtimeDependencies) {
			deps.requireRuntimeIdentity = func(int, int) error { return errors.New("wrong uid") }
		}},
		{name: "ephemeral state", edit: func(deps *runtimeDependencies) {
			deps.prepareEphemeralState = func(string, int, int) error { return errors.New("unsafe state") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := baseRuntimeDependencies()
			tc.edit(&deps)
			served := false
			deps.runServing = func(context.Context, config.Config, netbird.Options) error { served = true; return nil }
			if err := run(context.Background(), nil, mapEnvironment(testEgressEnvironment()), deps); err == nil {
				t.Fatal("run() error = nil")
			}
			if served {
				t.Fatal("serving started after preflight failure")
			}
		})
	}
}

func TestPrepareEphemeralState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := prepareEphemeralState(path, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatalf("prepareEphemeralState() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := prepareEphemeralState(path, os.Geteuid()+1, os.Getegid()); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareEphemeralState(path, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("overbroad directory mode accepted")
	}
}
