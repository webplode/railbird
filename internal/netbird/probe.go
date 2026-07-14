package netbird

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

// ProbeMeshTCP dials targets over the embed userspace stack (not kernel routes).
func ProbeMeshTCP(ctx context.Context, c *embed.Client, addr string) {
	ports := probePorts(os.Getenv("NB_PROBE_PORTS"))
	host := strings.TrimSpace(addr)
	if host == "" {
		return
	}
	log.Printf("mesh probe: userspace Dial to %s ports %v (kernel ping may fail without TUN)", host, ports)
	for _, port := range ports {
		target := net.JoinHostPort(host, strconv.Itoa(port))
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		conn, err := c.Dial(dctx, "tcp", target)
		cancel()
		if err != nil {
			log.Printf("mesh probe tcp %s: FAIL %v", target, err)
			continue
		}
		_ = conn.Close()
		log.Printf("mesh probe tcp %s: OK", target)
	}
}

func probePorts(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []int{80, 443}
	}
	out := make([]int, 0, 4)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			log.Printf("mesh probe: skip invalid port %q", p)
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return []int{80, 443}
	}
	return out
}