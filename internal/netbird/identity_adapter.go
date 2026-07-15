package netbird

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

type embedBootstrapFactory struct {
	base Options
}

// NewBootstrapClientFactory returns the production adapter used by the local
// bootstrap transaction. New constructs embed.Client but deliberately does
// not call Start; RunBootstrap owns the durable prepared-before-Start boundary.
func NewBootstrapClientFactory(base Options) BootstrapClientFactory {
	return &embedBootstrapFactory{base: base}
}

func (f *embedBootstrapFactory) New(_ context.Context, bootstrap BootstrapClientOptions) (BootstrapClient, error) {
	opts := f.base
	opts.StateDir = bootstrap.StateDir
	opts.SetupKey = bootstrap.SetupKey
	opts.PrivateKey = ""
	embedOpts, err := buildEmbedOptions(opts)
	if err != nil {
		return nil, err
	}
	client, err := embed.New(embedOpts)
	if err != nil {
		return nil, fmt.Errorf("embed.New: %w", err)
	}
	return &embedBootstrapClient{client: client, stopTimeout: opts.StopTimeout}, nil
}

type embedBootstrapClient struct {
	client      *embed.Client
	stopTimeout time.Duration
}

func (c *embedBootstrapClient) Start(ctx context.Context) error {
	return c.client.Start(ctx)
}

func (c *embedBootstrapClient) Status(context.Context) (BootstrapStatus, error) {
	return statusFromEmbedClient(c.client)
}

func (c *embedBootstrapClient) Stop(context.Context) error {
	return stopEmbedClient(c.client, c.stopTimeout)
}

func statusFromEmbedClient(client *embed.Client) (BootstrapStatus, error) {
	status, err := client.Status()
	if err != nil {
		return BootstrapStatus{}, err
	}
	return BootstrapStatus{
		PublicKey:           status.LocalPeerState.PubKey,
		ManagementConnected: status.ManagementState.Connected,
		SignalConnected:     status.SignalState.Connected,
	}, nil
}
