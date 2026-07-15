package netbird

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBuildEmbedOptionsEgress(t *testing.T) {
	const setupKey = "setup-key-must-not-leak"
	opts, err := buildEmbedOptions(Options{
		Mode:          config.ModeEgress,
		SetupKey:      setupKey,
		StateDir:      "/var/lib/railbird/netbird",
		DeviceName:    "railbird-egress",
		ManagementURL: "https://netbird.example.com",
	})
	if err != nil {
		t.Fatalf("buildEmbedOptions() error = %v", err)
	}

	if opts.NoUserspace {
		t.Fatal("NoUserspace = true, want false")
	}
	if !opts.BlockInbound {
		t.Fatal("BlockInbound = false, want true for egress")
	}
	if opts.ConfigPath != "/var/lib/railbird/netbird/config.json" {
		t.Fatalf("ConfigPath = %q", opts.ConfigPath)
	}
	if opts.StatePath != "/var/lib/railbird/netbird/state.json" {
		t.Fatalf("StatePath = %q", opts.StatePath)
	}
	if opts.SetupKey != setupKey || opts.PrivateKey != "" || opts.JWTToken != "" {
		t.Fatal("egress credentials were not passed exclusively as SetupKey")
	}
}

func TestWaitForConnectedRequiresBothControlPlanesAndValidIdentity(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	status, err := WaitForConnected(context.Background(), func() (BootstrapStatus, error) {
		calls++
		if calls == 1 {
			return BootstrapStatus{PublicKey: key.PublicKey().String(), ManagementConnected: true}, nil
		}
		return BootstrapStatus{PublicKey: key.PublicKey().String(), ManagementConnected: true, SignalConnected: true}, nil
	}, time.Millisecond)
	if err != nil || !status.ManagementConnected || !status.SignalConnected || calls != 2 {
		t.Fatalf("WaitForConnected() = %#v, %v after %d calls", status, err, calls)
	}
}

func TestWaitForConnectedHonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := WaitForConnected(ctx, func() (BootstrapStatus, error) {
		return BootstrapStatus{}, nil
	}, time.Millisecond)
	if err == nil {
		t.Fatal("WaitForConnected() error = nil")
	}
}

func TestWaitForConnectedPreservesLastStatusError(t *testing.T) {
	sentinel := errors.New("status unavailable")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := WaitForConnected(ctx, func() (BootstrapStatus, error) {
		return BootstrapStatus{}, sentinel
	}, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
		t.Fatalf("WaitForConnected() error = %v", err)
	}
}

func TestValidateServingIdentityBindsIngressStatusToPersistentKey(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Mode:              config.ModeIngress,
		PrivateKey:        privateKey.String(),
		ExpectedPublicKey: privateKey.PublicKey().String(),
	}
	if err := validateServingIdentity(opts, BootstrapStatus{PublicKey: privateKey.PublicKey().String()}); err != nil {
		t.Fatalf("matching ingress identity rejected: %v", err)
	}
	if err := validateServingIdentity(opts, BootstrapStatus{PublicKey: other.PublicKey().String()}); err == nil {
		t.Fatal("mismatched ingress identity accepted")
	}
	if err := validateServingIdentity(Options{Mode: config.ModeEgress, SetupKey: "setup"}, BootstrapStatus{PublicKey: other.PublicKey().String()}); err != nil {
		t.Fatalf("valid enrolled egress identity rejected: %v", err)
	}
}

func TestBuildEmbedOptionsIngress(t *testing.T) {
	const privateKey = "private-key-must-not-leak"
	opts, err := buildEmbedOptions(Options{
		Mode:       config.ModeIngress,
		PrivateKey: privateKey,
		StateDir:   "/data/netbird",
	})
	if err != nil {
		t.Fatalf("buildEmbedOptions() error = %v", err)
	}

	if opts.NoUserspace {
		t.Fatal("NoUserspace = true, want false")
	}
	if opts.BlockInbound {
		t.Fatal("BlockInbound = true, want false for ingress")
	}
	if opts.ConfigPath != "/data/netbird/config.json" || opts.StatePath != "/data/netbird/state.json" {
		t.Fatalf("state paths = (%q, %q)", opts.ConfigPath, opts.StatePath)
	}
	if opts.PrivateKey != privateKey || opts.SetupKey != "" || opts.JWTToken != "" {
		t.Fatal("ingress credentials were not passed exclusively as PrivateKey")
	}
}

func TestBuildEmbedOptionsRejectsInvalidIdentityOptionsWithoutLeakingSecrets(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{name: "no credential", opts: Options{Mode: config.ModeIngress}},
		{name: "multiple credentials", opts: Options{
			Mode: config.ModeIngress, SetupKey: "secret-setup", PrivateKey: "secret-private",
		}},
		{name: "invalid mode", opts: Options{Mode: config.Mode("sideways"), SetupKey: "secret-setup"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildEmbedOptions(tt.opts)
			if err == nil {
				t.Fatal("buildEmbedOptions() error = nil")
			}
			for _, secret := range []string{tt.opts.SetupKey, tt.opts.PrivateKey} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked credential: %v", err)
				}
			}
		})
	}
}
