package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/jratienza65/railbird/internal/config"
	"github.com/jratienza65/railbird/internal/forward"
	"github.com/jratienza65/railbird/internal/netbird"
)

func main() {
	cfg, err := config.Load(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}

	fwds, err := forward.Parse(cfg.Forwards)
	if err != nil {
		log.Fatalf("parse forwards: %v", err)
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		log.Fatalf("mkdir state: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c, err := netbird.New(ctx, netbird.Options{
		DeviceName:    cfg.DeviceName,
		ManagementURL: cfg.ManagementURL,
		SetupKey:      cfg.SetupKey,
		StateDir:      cfg.StateDir,
		LogLevel:      cfg.LogLevel,
		DNSLabels:     cfg.DNSLabels,
		MTU:           cfg.MTU,
	})
	if err != nil {
		log.Fatalf("netbird: %v", err)
	}
	defer c.Stop(context.Background())

	if probe := strings.TrimSpace(os.Getenv("NB_PROBE_ADDR")); probe != "" {
		go netbird.ProbeMeshTCP(ctx, c, probe)
	}

	static := forward.ParseStaticHosts(os.Getenv("NB_STATIC_HOSTS"))
	if len(static) > 0 {
		log.Printf("static hosts: %d entries (override DNS-over-TCP)", len(static))
	}
	tcpRes := forward.NewTCPResolver(cfg.DNSOverTCP, cfg.DNSResolver, c)
	res := forward.ChainResolver(static, tcpRes)
	if tcpRes != nil {
		log.Printf("dns-over-tcp enabled via %s (egress hostnames in FORWARDS)", cfg.DNSResolver)
		if name := strings.TrimSpace(os.Getenv("NB_PROBE_DNS")); name != "" {
			go netbird.ProbeDNSOverTCP(ctx, c, cfg.DNSResolver, name)
		}
	}

	var wg sync.WaitGroup
	for _, f := range fwds {
		wg.Add(1)
		go func(f forward.Forward) {
			defer wg.Done()
			if err := forward.Run(ctx, c, f, cfg.Mode, res); err != nil {
				log.Printf("forward %s: %v", f.ListenPort, err)
			}
		}(f)
	}

	wg.Wait()
}
