// Package proxy implements Mimlec's intercepting HTTP/HTTPS proxy. Clients
// configure it as their system/browser proxy; it records every transaction as
// a Flow, optionally pausing traffic for inspection and editing, then forwards
// it to the intended upstream server.
//
// Intended for authorised web-application security testing against systems the
// operator owns or has permission to assess.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorkemguler/mimlec/internal/cert"
)

// Config holds tunables for a Proxy. The zero value is not valid; use it via
// New which fills sensible defaults.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:8080".
	Addr string
	// CA issues per-host leaf certificates for HTTPS interception.
	CA *cert.Authority
	// UpstreamProxy, when set, routes outbound traffic through another proxy.
	UpstreamProxy string
	// InsecureUpstream disables verification of upstream server certificates.
	// Enabled by default because the operator is deliberately inspecting
	// traffic and target environments frequently use self-signed certs.
	InsecureUpstream bool
}

// Proxy is a running (or runnable) intercepting proxy instance.
type Proxy struct {
	cfg         Config
	ca          *cert.Authority
	interceptor *Interceptor
	transport   *http.Transport

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	running  bool

	// onFlow is called once per completed transaction. May be nil.
	onFlowMu sync.RWMutex
	onFlow   func(*Flow)

	// scopeMu guards the optional in-scope host filter.
	scopeMu sync.RWMutex
	inScope func(host string) bool
}

// New constructs a Proxy. cfg.CA is required.
func New(cfg Config) (*Proxy, error) {
	if cfg.CA == nil {
		return nil, errors.New("proxy: Config.CA is required")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	tr := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false, // we speak HTTP/1.1 to keep flows editable
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureUpstream, //nolint:gosec // deliberate for interception
			MinVersion:         tls.VersionTLS10,
		},
	}
	p := &Proxy{
		cfg:         cfg,
		ca:          cfg.CA,
		interceptor: newInterceptor(),
		transport:   tr,
	}
	return p, nil
}

// Interceptor exposes the interception controller for the UI layer.
func (p *Proxy) Interceptor() *Interceptor { return p.interceptor }

// OnFlow registers a callback invoked for every completed transaction.
func (p *Proxy) OnFlow(fn func(*Flow)) {
	p.onFlowMu.Lock()
	p.onFlow = fn
	p.onFlowMu.Unlock()
}

// OnHold registers a callback invoked whenever a transaction is paused by the
// interceptor and awaits a decision.
func (p *Proxy) OnHold(fn func(*Held)) { p.interceptor.setOnHold(fn) }

// SetScope restricts interception/recording to hosts for which fn returns
// true. A nil fn (the default) records everything.
func (p *Proxy) SetScope(fn func(host string) bool) {
	p.scopeMu.Lock()
	p.inScope = fn
	p.scopeMu.Unlock()
}

func (p *Proxy) hostInScope(host string) bool {
	p.scopeMu.RLock()
	fn := p.inScope
	p.scopeMu.RUnlock()
	if fn == nil {
		return true
	}
	return fn(host)
}

func (p *Proxy) emit(f *Flow) {
	p.onFlowMu.RLock()
	fn := p.onFlow
	p.onFlowMu.RUnlock()
	if fn != nil {
		fn(f)
	}
}

// Addr returns the address the proxy is (or will be) listening on.
func (p *Proxy) Addr() string { return p.cfg.Addr }

// Start binds the listener and serves in a background goroutine. It returns
// once the socket is accepting connections.
func (p *Proxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return errors.New("proxy: already running")
	}
	ln, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", p.cfg.Addr, err)
	}
	p.listener = ln
	p.cfg.Addr = ln.Addr().String()
	p.server = &http.Server{
		Handler:      http.HandlerFunc(p.handle),
		ReadTimeout:  0, // interception may pause reads indefinitely
		WriteTimeout: 0,
	}
	p.running = true
	go func() {
		_ = p.server.Serve(ln)
	}()
	return nil
}

// Stop gracefully shuts the proxy down.
func (p *Proxy) Stop(ctx context.Context) error {
	p.mu.Lock()
	srv := p.server
	p.running = false
	p.mu.Unlock()
	if srv == nil {
		return nil
	}
	// Release any paused transactions first. A held request blocks inside
	// hold() with its handler goroutine still running, so a graceful
	// Shutdown would otherwise wait on it until ctx expires (or forever, if
	// the caller passed a context without a deadline).
	p.interceptor.SetEnabled(false)
	p.interceptor.SetInterceptResponses(false)
	p.interceptor.ForwardAll()
	return srv.Shutdown(ctx)
}

// handle is the top-level HTTP handler. CONNECT establishes an HTTPS tunnel we
// terminate for inspection; everything else is a plain-HTTP proxy request.
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP proxies a plain (non-tunnelled) HTTP request.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	f := p.roundTrip("http", r.Host, r)
	if f == nil {
		http.Error(w, "dropped by interceptor", http.StatusForbidden)
		return
	}
	if f.Error != "" {
		http.Error(w, f.Error, http.StatusBadGateway)
		return
	}
	writeCapturedResponse(w, f)
}

// handleConnect terminates the client's TLS session using a generated leaf
// certificate, then serves the decrypted HTTP requests inside the tunnel.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	host := hostOnly(r.Host)
	leaf, err := p.ca.CertForName(host)
	if err != nil {
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS10,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Honour SNI so wildcard/virtual hosts get the right leaf.
			if hello.ServerName != "" {
				return p.ca.CertForName(hello.ServerName)
			}
			return leaf, nil
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	p.serveTunnel(tlsConn, r.Host)
}

// serveTunnel reads sequential HTTP requests off a decrypted connection and
// proxies each to the upstream authority, writing responses back in order.
func (p *Proxy) serveTunnel(conn net.Conn, authority string) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed the tunnel or sent garbage
		}
		req.URL.Scheme = "https"
		req.URL.Host = authority
		if req.Host == "" {
			req.Host = authority
		}

		f := p.roundTrip("https", authority, req)
		if f == nil {
			return // dropped: tear the tunnel down
		}
		if f.Error != "" {
			writeRawError(conn, f.Error)
			return
		}
		if err := writeCapturedResponseConn(conn, f); err != nil {
			return
		}
		if f.responseClose {
			return
		}
	}
}

// roundTrip captures a request, applies interception, forwards it upstream,
// captures the response, records the Flow, and returns it. A nil return means
// the transaction was dropped by the interceptor.
func (p *Proxy) roundTrip(scheme, authority string, req *http.Request) *Flow {
	start := time.Now()
	host := hostOnly(authority)
	recording := p.hostInScope(host)

	reqBody, _ := captureBody(&req.Body)
	rawReq := requestToRaw(req, reqBody)

	// Request-side interception.
	res := p.interceptor.hold(nextFlowID(), DirectionRequest, authority, req.Method, req.URL.String(), rawReq)
	if res.Decision == DecisionDrop {
		return nil
	}
	if res.EditedRaw != nil {
		edited, err := rawToRequest(res.EditedRaw, scheme, authority)
		if err == nil {
			req = edited
			reqBody, _ = captureBody(&req.Body)
			rawReq = res.EditedRaw
		}
	}

	f := &Flow{
		ID:      nextFlowID(),
		Scheme:  scheme,
		Method:  req.Method,
		Host:    authority,
		Path:    req.URL.RequestURI(),
		URL:     scheme + "://" + authority + req.URL.RequestURI(),
		Started: start,
		Request: Message{Raw: rawReq, Headers: req.Header.Clone(), Body: reqBody, ContentLength: int64(len(reqBody))},
	}

	outReq := prepareOutbound(req, reqBody)
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		f.Error = err.Error()
		f.Duration = time.Since(start).Milliseconds()
		if recording {
			p.emit(f)
		}
		return f
	}

	respBody, _ := captureBody(&resp.Body)
	rawResp := responseToRaw(resp, respBody)

	// Response-side interception.
	res = p.interceptor.hold(f.ID, DirectionResponse, authority, req.Method, f.URL, rawResp)
	if res.Decision == DecisionDrop {
		return nil
	}
	if res.EditedRaw != nil {
		if edited, perr := rawToResponse(res.EditedRaw, outReq); perr == nil {
			eb, _ := captureBody(&edited.Body)
			resp = edited
			respBody = eb
			rawResp = res.EditedRaw
		}
	}

	f.StatusCode = resp.StatusCode
	f.responseClose = resp.Close
	f.Response = Message{Raw: rawResp, Headers: resp.Header.Clone(), Body: respBody, ContentLength: int64(len(respBody))}
	f.Duration = time.Since(start).Milliseconds()

	if recording {
		p.emit(f)
	}
	return f
}

// prepareOutbound clones the inbound request into one suitable for the
// upstream transport: absolute URL, buffered body, hop-by-hop headers removed.
func prepareOutbound(req *http.Request, body []byte) *http.Request {
	out := req.Clone(context.Background())
	out.RequestURI = ""
	out.Body = io.NopCloser(bytesReader(body))
	out.ContentLength = int64(len(body))
	stripHopByHop(out.Header)
	return out
}

func hostOnly(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return authority
}
