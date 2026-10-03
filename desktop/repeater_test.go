package main

import (
	"encoding/json"
	"testing"

	"github.com/gorkemguler/kanca/internal/history"
	"github.com/gorkemguler/kanca/internal/proxy"
	"github.com/gorkemguler/kanca/internal/repeater"
)

func TestRepeaterTabsSerialiseRawAsText(t *testing.T) {
	const raw = "GET /api/products?id=3 HTTP/1.1\r\nHost: shop.example\r\n\r\n"
	a := &App{store: history.New(0), rep: repeater.New(true)}
	a.store.Add(&proxy.Flow{ID: 7, Scheme: "http", Host: "shop.example", Request: proxy.Message{Raw: []byte(raw)}})

	fromFlow, err := a.RepeaterFromFlow(7)
	if err != nil {
		t.Fatalf("RepeaterFromFlow: %v", err)
	}
	for name, tab := range map[string]*RepeaterTabView{
		"from flow": fromFlow,
		"new tab":   a.RepeaterNewTab("http", "shop.example", raw),
	} {
		b, err := json.Marshal(tab)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var got struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if got.Raw != raw {
			t.Errorf("%s: raw = %q, want the request text %q", name, got.Raw, raw)
		}
	}
}
