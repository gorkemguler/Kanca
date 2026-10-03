package sitemap

import (
	"testing"

	"github.com/gorkemguler/kanca/internal/proxy"
)

func mk(id int64, scheme, host, path, method string, status int) *proxy.Flow {
	return &proxy.Flow{
		ID: id, Scheme: scheme, Host: host, Path: path, Method: method,
		StatusCode: status, URL: scheme + "://" + host + path,
	}
}

func child(n *Node, name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestBuildTree(t *testing.T) {
	flows := []*proxy.Flow{
		mk(1, "https", "api.example.com", "/api/users", "GET", 200),
		mk(2, "https", "api.example.com", "/api/users/42", "GET", 200),
		mk(3, "https", "api.example.com", "/api/login?next=/", "POST", 401),
		mk(4, "https", "cdn.example.com", "/logo.png", "GET", 200),
	}
	roots := Build(flows)
	if len(roots) != 2 {
		t.Fatalf("roots = %d, want 2", len(roots))
	}
	// Sorted: api.example.com before cdn.example.com.
	if roots[0].Name != "api.example.com" || roots[1].Name != "cdn.example.com" {
		t.Fatalf("root order = %q, %q", roots[0].Name, roots[1].Name)
	}

	api := roots[0]
	if api.Count != 3 {
		t.Fatalf("api root count = %d, want 3", api.Count)
	}
	apiDir := child(api, "api")
	if apiDir == nil || apiDir.Count != 3 {
		t.Fatalf("api dir = %+v", apiDir)
	}
	users := child(apiDir, "users")
	if users == nil || users.Method != "GET" || users.Count != 2 {
		t.Fatalf("users node = %+v", users)
	}
	// /api/users/42 nests under users.
	if u42 := child(users, "42"); u42 == nil || u42.FlowID != 2 {
		t.Fatalf("users/42 node = %+v", u42)
	}
	// Query string must not create a node.
	login := child(apiDir, "login")
	if login == nil || login.StatusCode != 401 {
		t.Fatalf("login node = %+v", login)
	}
	if child(login, "") != nil {
		t.Fatal("query string created a blank child")
	}
}

func TestRootPathEndpoint(t *testing.T) {
	roots := Build([]*proxy.Flow{mk(1, "http", "x.test", "/", "GET", 200)})
	if len(roots) != 1 {
		t.Fatalf("roots = %d", len(roots))
	}
	// A request to "/" marks the root node itself as an endpoint.
	if roots[0].Method != "GET" || roots[0].Count != 1 {
		t.Fatalf("root endpoint = %+v", roots[0])
	}
}

func TestMostRecentWins(t *testing.T) {
	roots := Build([]*proxy.Flow{
		mk(1, "http", "x.test", "/a", "GET", 200),
		mk(5, "http", "x.test", "/a", "POST", 500),
	})
	a := child(roots[0], "a")
	if a.Method != "POST" || a.StatusCode != 500 || a.FlowID != 5 {
		t.Fatalf("most-recent did not win: %+v", a)
	}
	if a.Count != 2 {
		t.Fatalf("count = %d, want 2", a.Count)
	}
}
