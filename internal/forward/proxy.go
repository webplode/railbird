package forward

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

// dialKeepAlive is applied to local-side TCP dials in ingress mode. The mesh
// dialer manages its own keepalive.
const dialKeepAlive = 30 * time.Second

// proxy bridges in <-> target until either side closes. Half-close on EOF
// is best-effort: if the underlying conn doesn't expose CloseWrite the call
// is silently skipped (e.g. a TLS-wrapped conn).
func proxy(ctx context.Context, c MeshClient, in net.Conn, target string, mode config.Mode) {
	defer in.Close()

	out, err := dial(ctx, c, target, mode)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer out.Close()
	log.Printf("proxy %s <-> %s established", in.RemoteAddr(), target)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(out, in)
		log.Printf("copy in->out done bytes=%d err=%v", n, err)
		halfClose(out)
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(in, out)
		log.Printf("copy out->in done bytes=%d err=%v", n, err)
		halfClose(in)
	}()
	wg.Wait()
	log.Printf("proxy %s <-> %s closed", in.RemoteAddr(), target)
}

// dial picks the right outbound dialer for the given mode.
func dial(ctx context.Context, c MeshClient, target string, mode config.Mode) (net.Conn, error) {
	switch mode {
	case config.ModeIngress:
		d := net.Dialer{KeepAlive: dialKeepAlive}
		return d.DialContext(ctx, "tcp", target)
	case config.ModeEgress:
		return c.Dial(ctx, "tcp", target)
	}
	return nil, errInvalidMode(mode)
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
