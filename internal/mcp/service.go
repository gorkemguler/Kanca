package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Service runs a Server's endpoint on a loopback address.
type Service struct {
	Server *Server

	mu   sync.Mutex
	http *http.Server
	addr string
}

// Start listens on addr (which must be a loopback address) and serves /mcp
// with token. It replaces any endpoint already running.
func (s *Service) Start(addr, token string) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	_ = s.Stop()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mcp: listen on %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.Server.Handler(token))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	s.mu.Lock()
	s.http, s.addr = srv, ln.Addr().String()
	s.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// Stop shuts the endpoint down; it is a no-op when nothing is running.
func (s *Service) Stop() error {
	s.mu.Lock()
	srv := s.http
	s.http, s.addr = nil, ""
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// Addr returns the listening address, or "" when stopped.
func (s *Service) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("mcp: bad address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("mcp: the AI endpoint only listens on a loopback address (e.g. 127.0.0.1)")
}
