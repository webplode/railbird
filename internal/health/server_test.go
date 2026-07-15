package health

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestStartBindFailure(t *testing.T) {
	want := errors.New("bind failed")
	called := false
	server, err := StartWithOptions(8080, Options{
		Listen: func(network, address string) (net.Listener, error) {
			called = true
			if network != "tcp" || address != "[::]:8080" {
				t.Fatalf("listen(%q, %q)", network, address)
			}
			return nil, want
		},
		NewServer: func(http.Handler) HTTPServer {
			t.Fatal("HTTP server must not be constructed after bind failure")
			return nil
		},
	})
	if !called || server != nil || !errors.Is(err, want) {
		t.Fatalf("server=%v err=%v called=%v", server, err, called)
	}
}

func TestReadinessTransitionsAndOnlyReadyRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := StartWithOptions(8080, Options{
		Listen: func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != "[::]:8080" {
				t.Fatalf("listen(%q, %q)", network, address)
			}
			return listener, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-server.Terminal()
	})

	url := "http://" + listener.Addr().String()
	assertStatus(t, url+"/ready", http.StatusServiceUnavailable, "not ready\n")
	assertStatus(t, url+"/other", http.StatusNotFound, "404 page not found\n")
	if !server.SetReady(true) || !server.IsReady() {
		t.Fatal("failed to mark ready")
	}
	assertStatus(t, url+"/ready", http.StatusOK, "ready\n")
	if !server.SetReady(false) || server.IsReady() {
		t.Fatal("failed to mark temporarily unready")
	}
	assertStatus(t, url+"/ready", http.StatusServiceUnavailable, "not ready\n")
	server.SetReady(true)
	server.BeginDrain()
	if server.IsReady() || server.SetReady(true) {
		t.Fatal("draining server reopened readiness")
	}
	assertStatus(t, url+"/ready", http.StatusServiceUnavailable, "not ready\n")
}

func TestUnexpectedServeFailureIsTerminalAndUnready(t *testing.T) {
	want := errors.New("serve failed")
	fake := &fakeHTTPServer{serveResult: make(chan error, 1)}
	listener := &stubListener{}
	server, err := StartWithOptions(8080, Options{
		Listen:    func(string, string) (net.Listener, error) { return listener, nil },
		NewServer: func(http.Handler) HTTPServer { return fake },
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetReady(true)
	fake.serveResult <- want

	select {
	case err := <-server.Terminal():
		if !errors.Is(err, want) {
			t.Fatalf("terminal err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal error was not published")
	}
	if server.IsReady() || server.SetReady(true) {
		t.Fatal("terminal server remained or became ready")
	}
}

func TestNilServeExitIsUnexpected(t *testing.T) {
	fake := &fakeHTTPServer{serveResult: make(chan error, 1)}
	server, err := StartWithOptions(8080, Options{
		Listen:    func(string, string) (net.Listener, error) { return &stubListener{}, nil },
		NewServer: func(http.Handler) HTTPServer { return fake },
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.serveResult <- nil
	if err := <-server.Terminal(); !errors.Is(err, ErrUnexpectedServeExit) {
		t.Fatalf("terminal err=%v", err)
	}
}

func TestShutdownIsCleanAndUsesCallerDeadline(t *testing.T) {
	fake := &fakeHTTPServer{serveResult: make(chan error, 1)}
	server, err := StartWithOptions(8080, Options{
		Listen:    func(string, string) (net.Listener, error) { return &stubListener{}, nil },
		NewServer: func(http.Handler) HTTPServer { return fake },
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetReady(true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if server.IsReady() || fake.shutdownContext() != ctx {
		t.Fatal("shutdown did not latch readiness or preserve context")
	}
	fake.serveResult <- http.ErrServerClosed
	select {
	case err := <-server.Terminal():
		if err != nil {
			t.Fatalf("clean shutdown reported %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("clean terminal result was not published")
	}
}

func TestShutdownReturnsWhenContextExpires(t *testing.T) {
	fake := &fakeHTTPServer{
		serveResult: make(chan error, 1),
		shutdown: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	server, err := StartWithOptions(8080, Options{
		Listen:    func(string, string) (net.Listener, error) { return &stubListener{}, nil },
		NewServer: func(http.Handler) HTTPServer { return fake },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown err=%v", err)
	}
	fake.serveResult <- http.ErrServerClosed
	<-server.Terminal()
}

func assertStatus(t *testing.T, url string, wantStatus int, wantBody string) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus || string(body) != wantBody {
		t.Fatalf("GET %s: status=%d body=%q", url, response.StatusCode, body)
	}
}

type fakeHTTPServer struct {
	serveResult chan error
	shutdown    func(context.Context) error
	mu          sync.Mutex
	shutdownCtx context.Context
}

func (s *fakeHTTPServer) Serve(net.Listener) error {
	return <-s.serveResult
}

func (s *fakeHTTPServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.shutdownCtx = ctx
	s.mu.Unlock()
	if s.shutdown != nil {
		return s.shutdown(ctx)
	}
	return nil
}

func (s *fakeHTTPServer) shutdownContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shutdownCtx
}

type stubListener struct{}

func (*stubListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (*stubListener) Close() error              { return nil }
func (*stubListener) Addr() net.Addr            { return stubAddr("stub") }

type stubAddr string

func (stubAddr) Network() string  { return "stub" }
func (a stubAddr) String() string { return string(a) }
