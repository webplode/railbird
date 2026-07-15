// Package forward parses port-forward specs and runs the listener/proxy
// loop that bridges the local network and a NetBird mesh.
package forward

import (
	"github.com/jratienza65/railbird/internal/forward/spec"
)

// Forward describes a single listen-port → target mapping.
//
// Spec formats accepted by Parse:
//
//	host:port            listen on :port, dial host:port
//	lport=host:port      listen on :lport, dial host:port
type Forward = spec.Forward

// Parse parses a comma-separated list of forward specs. Whitespace around
// each entry is trimmed. Empty or malformed entries are rejected.
func Parse(s string) ([]Forward, error) {
	return spec.Parse(s)
}
