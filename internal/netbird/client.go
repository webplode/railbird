// Package netbird wraps the embedded NetBird client lifecycle (New + Start)
// behind a small Options struct, isolating embed-specific knobs from the
// rest of the binary.
package netbird

import (
	"context"
	"crypto/subtle"
	"fmt"
	"path/filepath"
	"time"

	"github.com/jratienza65/railbird/internal/config"
	"github.com/netbirdio/netbird/client/embed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Options holds the embed.Client knobs railbird actually sets. Anything
// outside this struct stays at embed defaults.
type Options struct {
	DeviceName        string
	ManagementURL     string
	SetupKey          string
	PrivateKey        string
	ExpectedPublicKey string
	Mode              config.Mode
	StateDir          string
	LogLevel          string
	DNSLabels         []string
	MTU               int // 0 = use NetBird default (1280)
	StopTimeout       time.Duration
}

// New constructs and starts an embedded NetBird client. The caller owns the
// returned *embed.Client and must call its Stop method when done.
func New(ctx context.Context, opts Options) (*embed.Client, error) {
	embedOpts, err := buildEmbedOptions(opts)
	if err != nil {
		return nil, err
	}
	c, err := embed.New(embedOpts)
	if err != nil {
		return nil, fmt.Errorf("embed.New: %w", err)
	}
	if err := c.Start(ctx); err != nil {
		_ = stopEmbedClient(c, opts.StopTimeout)
		return nil, fmt.Errorf("netbird start: %w", err)
	}
	status, err := WaitForConnected(ctx, func() (BootstrapStatus, error) {
		return statusFromEmbedClient(c)
	}, 100*time.Millisecond)
	if err != nil {
		_ = stopEmbedClient(c, opts.StopTimeout)
		return nil, fmt.Errorf("netbird connected status: %w", err)
	}
	if err := validateServingIdentity(opts, status); err != nil {
		_ = stopEmbedClient(c, opts.StopTimeout)
		return nil, err
	}
	return c, nil
}

func validateServingIdentity(opts Options, status BootstrapStatus) error {
	if opts.Mode != config.ModeIngress || opts.PrivateKey == "" {
		return nil
	}
	privateKey, err := wgtypes.ParseKey(opts.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid persistent private key")
	}
	expected := privateKey.PublicKey()
	if opts.ExpectedPublicKey != "" {
		explicit, err := wgtypes.ParseKey(opts.ExpectedPublicKey)
		if err != nil || subtle.ConstantTimeCompare(expected[:], explicit[:]) != 1 {
			return fmt.Errorf("persistent expected public key does not match private key")
		}
		expected = explicit
	}
	connected, err := wgtypes.ParseKey(status.PublicKey)
	if err != nil || subtle.ConstantTimeCompare(expected[:], connected[:]) != 1 {
		return fmt.Errorf("connected persistent identity public key mismatch")
	}
	return nil
}

// WaitForConnected polls status until both control-plane connections and the
// local public identity are present, or the caller's startup context expires.
func WaitForConnected(ctx context.Context, status func() (BootstrapStatus, error), interval time.Duration) (BootstrapStatus, error) {
	if status == nil {
		return BootstrapStatus{}, fmt.Errorf("netbird status function is required")
	}
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr error
	for {
		current, err := status()
		if err == nil && current.ManagementConnected && current.SignalConnected && validPublicKey(current.PublicKey) {
			return current, nil
		}
		if err != nil {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return BootstrapStatus{}, fmt.Errorf("wait for connected status: %w (last status error: %v)", ctx.Err(), lastErr)
			}
			return BootstrapStatus{}, fmt.Errorf("wait for connected status: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func stopEmbedClient(client *embed.Client, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return client.Stop(ctx)
}

// buildEmbedOptions is kept pure so mode and identity invariants can be
// verified without constructing a NetBird client or touching persistent state.
func buildEmbedOptions(opts Options) (embed.Options, error) {
	if opts.Mode != config.ModeIngress && opts.Mode != config.ModeEgress {
		return embed.Options{}, fmt.Errorf("invalid netbird mode")
	}
	if (opts.SetupKey == "") == (opts.PrivateKey == "") {
		return embed.Options{}, fmt.Errorf("exactly one netbird credential is required")
	}

	embedOpts := embed.Options{
		DeviceName:    opts.DeviceName,
		SetupKey:      opts.SetupKey,
		PrivateKey:    opts.PrivateKey,
		ManagementURL: opts.ManagementURL,
		ConfigPath:    filepath.Join(opts.StateDir, "config.json"),
		StatePath:     filepath.Join(opts.StateDir, "state.json"),
		DNSLabels:     opts.DNSLabels,
		LogLevel:      opts.LogLevel,
		// Default embed userspace (NoUserspace false): Dial/Listen work without TUN — required on Railway.
		NoUserspace:  false,
		BlockInbound: opts.Mode == config.ModeEgress,
	}
	if opts.MTU > 0 {
		mtu := uint16(opts.MTU)
		embedOpts.MTU = &mtu
	}
	return embedOpts, nil
}
