// Package forward parses port-forward specs and runs the listener/proxy
// loop that bridges the local network and a NetBird mesh.
package forward

import (
	"fmt"
	"net"
	"strings"
)

// Forward describes a single listen-port → target mapping.
//
// Spec formats accepted by Parse:
//
//	host:port            listen on :port, dial host:port
//	lport=host:port      listen on :lport, dial host:port
type Forward struct {
	ListenPort string
	Target     string
}

// Parse parses a comma-separated list of forward specs. Whitespace around
// each entry is trimmed; empty entries are dropped. Returns an error if the
// resulting list is empty or any entry is malformed.
func Parse(s string) ([]Forward, error) {
	var out []Forward

	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if i := strings.Index(item, "="); i >= 0 {
			lport := strings.TrimSpace(item[:i])
			target := strings.TrimSpace(item[i+1:])

			if _, _, err := net.SplitHostPort(target); err != nil {
				return nil, fmt.Errorf("invalid target %q: %w", item, err)
			}

			out = append(out, Forward{ListenPort: lport, Target: target})
			continue
		}

		_, port, err := net.SplitHostPort(item)

		if err != nil {
			return nil, fmt.Errorf("invalid forward %q (need host:port or lport=host:port): %w", item, err)
		}

		out = append(out, Forward{ListenPort: port, Target: item})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no forwards parsed")
	}
	return out, nil
}
