// Package health provides the lifecycle-only Railway readiness endpoint.
package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// ErrUnexpectedServeExit reports a Serve implementation that stopped without
// either an error or a deliberate http.ErrServerClosed result.
var ErrUnexpectedServeExit = errors.New("health HTTP server exited unexpectedly")

const (
	stateUnready uint32 = iota
	stateReady
	stateDraining
	stateTerminal

	healthReadHeaderTimeout = 2 * time.Second
	healthReadTimeout       = 3 * time.Second
	healthWriteTimeout      = 3 * time.Second
	healthIdleTimeout       = 5 * time.Second
	healthMaxHeaderBytes    = 8 << 10
)

// HTTPServer is the subset of http.Server used by the readiness service.
// It is exported so tests and application wiring can inject deterministic
// implementations without opening additional health semantics.
type HTTPServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

// Options contains factories used during startup. A nil factory selects the
// production net/http implementation.
type Options struct {
	Listen    func(network, address string) (net.Listener, error)
	NewServer func(handler http.Handler) HTTPServer
}

// Server owns the bound readiness listener and its lifecycle state.
type Server struct {
	http     HTTPServer
	state    atomic.Uint32
	terminal chan error
}

// Start synchronously binds [::]:port, then starts serving in the background.
// A successful return proves the health port was reserved before downstream
// startup begins.
func Start(port int) (*Server, error) {
	return StartWithOptions(port, Options{})
}

// StartWithOptions is Start with injectable listener and HTTP server factories.
func StartWithOptions(port int, options Options) (*Server, error) {
	listen := options.Listen
	if listen == nil {
		listen = net.Listen
	}
	newServer := options.NewServer
	if newServer == nil {
		newServer = func(handler http.Handler) HTTPServer {
			return &http.Server{
				Handler:           handler,
				ReadHeaderTimeout: healthReadHeaderTimeout,
				ReadTimeout:       healthReadTimeout,
				WriteTimeout:      healthWriteTimeout,
				IdleTimeout:       healthIdleTimeout,
				MaxHeaderBytes:    healthMaxHeaderBytes,
			}
		}
	}

	listener, err := listen("tcp", net.JoinHostPort("::", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	service := &Server{terminal: make(chan error, 1)}
	service.http = newServer(http.HandlerFunc(service.serveHTTP))
	if service.http == nil {
		_ = listener.Close()
		return nil, fmt.Errorf("health HTTP server factory returned nil")
	}

	go service.serve(listener)
	return service, nil
}

// SetReady changes ordinary startup readiness. Once drain or termination has
// begun, readiness is latched false and cannot be reopened.
func (s *Server) SetReady(ready bool) bool {
	if ready {
		for {
			state := s.state.Load()
			switch state {
			case stateReady:
				return true
			case stateUnready:
				if s.state.CompareAndSwap(stateUnready, stateReady) {
					return true
				}
			default:
				return false
			}
		}
	}

	return s.state.CompareAndSwap(stateReady, stateUnready) || s.state.Load() == stateUnready
}

// BeginDrain immediately and permanently makes the endpoint unready while the
// HTTP server remains available to report 503 during application draining.
func (s *Server) BeginDrain() {
	for {
		state := s.state.Load()
		if state >= stateDraining || s.state.CompareAndSwap(state, stateDraining) {
			return
		}
	}
}

// IsReady reports the current lifecycle readiness state.
func (s *Server) IsReady() bool {
	return s.state.Load() == stateReady
}

// Terminal returns a one-slot channel that receives exactly one value when
// Serve exits, then closes. A nil value denotes deliberate clean shutdown;
// a non-nil value is an unexpected terminal Serve failure.
func (s *Server) Terminal() <-chan error {
	return s.terminal
}

// Shutdown latches readiness false and delegates bounded shutdown to the HTTP
// server. The caller-provided context is the shutdown deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.BeginDrain()
	return s.http.Shutdown(ctx)
}

func (s *Server) serve(listener net.Listener) {
	err := s.http.Serve(listener)
	if err == nil {
		err = ErrUnexpectedServeExit
	} else if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	s.state.Store(stateTerminal)
	s.terminal <- err
	close(s.terminal)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ready" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !s.IsReady() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}
