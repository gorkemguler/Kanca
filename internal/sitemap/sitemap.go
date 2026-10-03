// Package sitemap arranges captured flows into a per-host tree of URL paths,
// giving a structural view of a target (which endpoints exist, nested under
// their directories) rather than a flat request log.
package sitemap

import (
	"sort"
	"strings"

	"github.com/gorkemguler/kanca/internal/proxy"
)

// Node is one entry in the tree. A node with a Method is an observed endpoint
// (a request was made to exactly its Path); interior directory nodes have no
// Method. Count is the number of observed requests at or below the node.
type Node struct {
	Name       string  `json:"name"`             // path segment label, or the host at the root
	Path       string  `json:"path"`             // full path from the host root ("/api/users")
	URL        string  `json:"url,omitempty"`    // full URL, when this node is an endpoint
	Method     string  `json:"method,omitempty"` // last observed method at this exact path
	StatusCode int     `json:"statusCode,omitempty"`
	FlowID     int64   `json:"flowId,omitempty"`
	Count      int     `json:"count"`
	Children   []*Node `json:"children,omitempty"`
}

// Build groups flows by scheme://host and returns one root Node per host, each
// holding the path tree beneath it. Roots and children are sorted by name for
// stable rendering.
func Build(flows []*proxy.Flow) []*Node {
	roots := map[string]*Node{}
	var order []string

	for _, f := range flows {
		hostKey := f.Scheme + "://" + f.Host
		root, ok := roots[hostKey]
		if !ok {
			root = &Node{Name: f.Host, Path: "/"}
			roots[hostKey] = root
			order = append(order, hostKey)
		}
		insert(root, f, hostKey)
	}

	out := make([]*Node, 0, len(order))
	for _, k := range order {
		out = append(out, roots[k])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	for _, r := range out {
		sortTree(r)
	}
	return out
}

// insert walks a flow's path segments from root, creating directory nodes as
// needed and marking the final node as an endpoint.
func insert(root *Node, f *proxy.Flow, hostKey string) {
	root.Count++
	path := pathOnly(f.Path)
	segments := splitPath(path)

	cur := root
	built := ""
	for _, seg := range segments {
		built += "/" + seg
		child := findChild(cur, seg)
		if child == nil {
			child = &Node{Name: seg, Path: built}
			cur.Children = append(cur.Children, child)
		}
		child.Count++
		cur = child
	}
	// cur is the node for the flow's exact path (root itself when path is "/").
	// Record endpoint metadata; the highest flow ID (most recent) wins.
	if f.ID >= cur.FlowID {
		cur.Method = f.Method
		cur.StatusCode = f.StatusCode
		cur.FlowID = f.ID
		cur.URL = f.URL
	}
}

func findChild(n *Node, name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func sortTree(n *Node) {
	sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Name < n.Children[j].Name })
	for _, c := range n.Children {
		sortTree(c)
	}
}

// pathOnly strips the query string; the tree is keyed on path structure.
func pathOnly(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// splitPath breaks "/api/users/42" into ["api","users","42"], dropping empty
// segments so a trailing slash doesn't create a blank node.
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
