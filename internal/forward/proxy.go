package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

const (
	defaultDialAttemptTimeout = 5 * time.Second
	defaultDialTotalTimeout   = 15 * time.Second
	defaultTCPKeepAlive       = 30 * time.Second
)

// DialOptions bounds outbound connection establishment. TotalTimeout includes
// hostname resolution and every address attempt.
type DialOptions struct {
	AttemptTimeout time.Duration
	TotalTimeout   time.Duration
	TCPKeepAlive   time.Duration
}

// ProxyOptions controls connection establishment and optional activity-based
// idle expiry. IdleTimeout zero leaves database-style quiet sessions alone.
type ProxyOptions struct {
	Dial        DialOptions
	IdleTimeout time.Duration
}

type copyResult struct {
	direction string
	bytes     int64
	err       error
}

func defaultProxyOptions() ProxyOptions {
	return ProxyOptions{Dial: DialOptions{
		AttemptTimeout: defaultDialAttemptTimeout,
		TotalTimeout:   defaultDialTotalTimeout,
		TCPKeepAlive:   defaultTCPKeepAlive,
	}}
}

// Proxy bridges in <-> target until both directions finish or ctx is
// cancelled. A terminal copy error closes both sides so the peer goroutine
// cannot leak. EOF retains best-effort half-close semantics.
func Proxy(ctx context.Context, c MeshClient, in net.Conn, target string, mode config.Mode, res HostResolver, opts ProxyOptions) error {
	if in == nil {
		return fmt.Errorf("proxy input connection is nil")
	}
	defer in.Close()

	out, err := DialTarget(ctx, c, target, mode, res, opts.Dial)
	if err != nil {
		return err
	}
	defer out.Close()
	configureTCPKeepAlive(in, normalizeKeepAlive(opts.Dial.TCPKeepAlive))
	log.Printf("proxy target=%s state=established", redactedTarget(target))

	touch := func() {}
	if opts.IdleTimeout > 0 {
		var deadlineMu sync.Mutex
		touch = func() {
			deadlineMu.Lock()
			deadline := time.Now().Add(opts.IdleTimeout)
			_ = in.SetDeadline(deadline)
			_ = out.SetDeadline(deadline)
			deadlineMu.Unlock()
		}
		touch()
	}

	results := make(chan copyResult, 2)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = in.Close()
			_ = out.Close()
		})
	}

	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-done:
		}
	}()

	go copyDirection(results, "in->out", out, in, touch)
	go copyDirection(results, "out->in", in, out, touch)

	first := <-results
	log.Printf("proxy target=%s direction=%s bytes=%d result=%s", redactedTarget(target), first.direction, first.bytes, networkFailureClass(first.err))
	if first.err != nil {
		closeBoth()
	} else if first.direction == "in->out" {
		halfClose(out)
	} else {
		halfClose(in)
	}

	second := <-results
	log.Printf("proxy target=%s direction=%s bytes=%d result=%s", redactedTarget(target), second.direction, second.bytes, networkFailureClass(second.err))
	if second.err != nil {
		closeBoth()
	} else if second.direction == "in->out" {
		halfClose(out)
	} else {
		halfClose(in)
	}
	close(done)
	closeBoth()
	log.Printf("proxy target=%s state=closed", redactedTarget(target))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(
		redactNetworkError(first.direction, normalizeCopyError(first.err)),
		redactNetworkError(second.direction, normalizeCopyError(second.err)),
	)
}

func copyDirection(results chan<- copyResult, direction string, dst, src net.Conn, touch func()) {
	n, err := io.Copy(activityWriter{Writer: dst, touch: touch}, activityReader{Reader: src, touch: touch})
	results <- copyResult{direction: direction, bytes: n, err: err}
}

// DialTarget resolves and attempts each approved target address within a
// single total budget. Errors retain classification while formatting omits
// internal addresses.
func DialTarget(ctx context.Context, c MeshClient, target string, mode config.Mode, res HostResolver, opts DialOptions) (net.Conn, error) {
	opts = normalizeDialOptions(opts)
	totalCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	targets, err := ResolveEgressTargets(totalCtx, target, mode, res)
	if err != nil {
		return nil, err
	}

	var failures []error
	for i, candidate := range targets {
		if err := totalCtx.Err(); err != nil {
			failures = append(failures, redactNetworkError(fmt.Sprintf("attempt=%d/%d", i+1, len(targets)), err))
			break
		}
		attemptStarted := time.Now()
		attemptCtx, attemptCancel := context.WithTimeout(totalCtx, opts.AttemptTimeout)
		conn, dialErr := dialCandidate(attemptCtx, c, candidate, mode, opts.TCPKeepAlive)
		attemptCancel()
		if dialErr == nil {
			log.Printf("dial target=%s attempt=%d/%d duration=%s result=connected", redactedTarget(target), i+1, len(targets), time.Since(attemptStarted).Round(time.Millisecond))
			return conn, nil
		}
		failures = append(failures, redactNetworkError(
			fmt.Sprintf("attempt=%d/%d duration=%s", i+1, len(targets), time.Since(attemptStarted).Round(time.Millisecond)),
			dialErr,
		))
	}
	return nil, fmt.Errorf("dial target=%s: %w", redactedTarget(target), errors.Join(failures...))
}

func dialCandidate(ctx context.Context, c MeshClient, target string, mode config.Mode, keepAlive time.Duration) (net.Conn, error) {
	switch mode {
	case config.ModeIngress:
		d := net.Dialer{KeepAlive: dialerKeepAlive(keepAlive)}
		conn, err := d.DialContext(ctx, "tcp", target)
		if err == nil {
			configureTCPKeepAlive(conn, keepAlive)
		}
		return conn, err
	case config.ModeEgress:
		if c == nil {
			return nil, fmt.Errorf("mesh client is nil")
		}
		conn, err := c.Dial(ctx, "tcp", target)
		if err == nil {
			configureTCPKeepAlive(conn, keepAlive)
		}
		return conn, err
	default:
		return nil, errInvalidMode(mode)
	}
}

func normalizeDialOptions(opts DialOptions) DialOptions {
	if opts.AttemptTimeout <= 0 {
		opts.AttemptTimeout = defaultDialAttemptTimeout
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = defaultDialTotalTimeout
	}
	if opts.AttemptTimeout > opts.TotalTimeout {
		opts.AttemptTimeout = opts.TotalTimeout
	}
	if opts.TCPKeepAlive < 0 {
		opts.TCPKeepAlive = 0
	}
	return opts
}

func normalizeKeepAlive(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}

func dialerKeepAlive(value time.Duration) time.Duration {
	if value == 0 {
		return -1
	}
	return value
}

func configureTCPKeepAlive(conn net.Conn, interval time.Duration) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if interval == 0 {
		_ = tcp.SetKeepAlive(false)
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(interval)
}

type activityReader struct {
	io.Reader
	touch func()
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.touch()
	}
	return n, err
}

type activityWriter struct {
	io.Writer
	touch func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.touch()
	}
	return n, err
}

func normalizeCopyError(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
