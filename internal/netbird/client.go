// Package netbird wraps the embedded NetBird client lifecycle (New + Start)
// behind a small Options struct, isolating embed-specific knobs from the
// rest of the binary.
package netbird

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/netbirdio/netbird/client/embed"
)

// Options holds the embed.Client knobs railbird actually sets. Anything
// outside this struct stays at embed defaults.
type Options struct {
	DeviceName    string
	ManagementURL string
	SetupKey      string
	StateDir      string
	LogLevel      string
	DNSLabels     []string
	MTU           int // 0 = use NetBird default (1280)
}

// New constructs and starts an embedded NetBird client. The caller owns the
// returned *embed.Client and must call its Stop method when done.
func New(ctx context.Context, opts Options) (*embed.Client, error) {
	embedOpts := embed.Options{
		DeviceName:    opts.DeviceName,
		SetupKey:      opts.SetupKey,
		ManagementURL: opts.ManagementURL,
		ConfigPath:    filepath.Join(opts.StateDir, "config.json"),
		StatePath:     filepath.Join(opts.StateDir, "state.json"),
		DNSLabels:     opts.DNSLabels,
		LogLevel:      opts.LogLevel,
		// Default embed userspace (NoUserspace false): Dial/Listen work without TUN — required on Railway.
		NoUserspace: false,
	}
	if opts.MTU > 0 {
		mtu := uint16(opts.MTU)
		embedOpts.MTU = &mtu
	}
	c, err := embed.New(embedOpts)
	if err != nil {
		return nil, fmt.Errorf("embed.New: %w", err)
	}
	if err := c.Start(ctx); err != nil {
		return nil, fmt.Errorf("netbird start: %w", err)
	}
	return c, nil
}
