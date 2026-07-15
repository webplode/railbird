package forward

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// redactedTarget preserves the target port and a stable host correlation key
// without exposing internal DNS names or IP inventory in logs and errors.
func redactedTarget(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "host#invalid"
	}
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	digest := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("host#%x:%s", digest[:5], port)
}

// safeNetworkError retains errors.Is/errors.As behavior for control flow while
// ensuring ordinary formatting never prints net.OpError addresses or raw DNS
// names returned by lower layers.
type safeNetworkError struct {
	prefix string
	class  string
	cause  error
}

func (e *safeNetworkError) Error() string {
	if e.prefix == "" {
		return e.class
	}
	return e.prefix + ": " + e.class
}

func (e *safeNetworkError) Unwrap() error { return e.cause }

func redactNetworkError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return &safeNetworkError{prefix: prefix, class: networkFailureClass(err), cause: err}
}

func networkFailureClass(err error) string {
	if err == nil {
		return "ok"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host unreachable"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken pipe"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "network failure"
}
