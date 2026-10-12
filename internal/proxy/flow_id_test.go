package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHeldItemsShareTheFlowIDAndIDsDontSkip(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	p := startTestProxy(t)
	ic := p.Interceptor()
	ic.SetEnabled(true)
	ic.SetInterceptResponses(true)
	held := make(chan *Held, 4)
	p.OnHold(func(h *Held) {
		held <- h
		ic.Resolve(h.ID, DecisionForward, nil)
	})
	flows := make(chan *Flow, 2)
	p.OnFlow(func(f *Flow) { flows <- f })
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	var ids []int64
	for i := 0; i < 2; i++ {
		resp, err := client.Get(backend.URL + "/")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		req, res, f := <-held, <-held, <-flows
		if req.Direction != DirectionRequest || res.Direction != DirectionResponse {
			t.Fatalf("hold order: %s then %s", req.Direction, res.Direction)
		}
		if req.ID != f.ID || res.ID != f.ID {
			t.Fatalf("held request #%d and response #%d belong to flow #%d", req.ID, res.ID, f.ID)
		}
		ids = append(ids, f.ID)
	}
	if ids[1] != ids[0]+1 {
		t.Fatalf("consecutive flows got IDs %v; numbers should not skip", ids)
	}
}
