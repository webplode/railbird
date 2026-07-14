package forward

import (
	"context"
	"log"
	"net"

	"github.com/jratienza65/railbird/internal/config"
)

// MeshClient is the subset of the NetBird embedded client used by the
// forward runner. Defined as an interface so tests can swap in a loopback
// fake.
type MeshClient interface {
	ListenTCP(address string) (net.Listener, error)
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Run binds a listener and serves connections for one Forward until ctx is
// cancelled or the listener fails to bind. The bind error is returned so
// callers can fail-fast at startup; once the accept loop is running,
// transient errors are logged and ignored.
//
// Mode selects the topology:
//
//	ingress  listener binds on the mesh,  dial is local
//	egress   listener binds locally,      dial goes through the mesh
func Run(ctx context.Context, c MeshClient, f Forward, mode config.Mode) error {
	ln, err := listen(c, f.ListenPort, mode)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("forward [%s]: listener=%s -> %s", mode, ln.Addr(), f.Target)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		in, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("accept :%s: %v", f.ListenPort, err)
			continue
		}
		log.Printf("accept :%s from %s", f.ListenPort, in.RemoteAddr())
		go proxy(ctx, c, in, f.Target, mode)
	}
}

// listen binds the appropriate listener for the given mode.
func listen(c MeshClient, port string, mode config.Mode) (net.Listener, error) {
	switch mode {
	case config.ModeIngress:
		return c.ListenTCP(":" + port)
	case config.ModeEgress:
		return net.Listen("tcp", ":"+port)
	}
	return nil, &net.OpError{Op: "listen", Err: errInvalidMode(mode)}
}

type errInvalidMode config.Mode

func (e errInvalidMode) Error() string { return "invalid mode: " + string(e) }
