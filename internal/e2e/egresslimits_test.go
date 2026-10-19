package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// egressGet is the backend side of the egress_get tool: one request to
// http://127.0.0.1:port/path through HTTP_PROXY, with a capability from the call's _meta and a
// body of n bytes (POST) when n > 0. It returns "<status> <reason>".
func egressGet(meta map[string]any, port int, path string, n int) string {
	target := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	var auth pipeline.EgressAuth
	raw, _ := json.Marshal(meta[pipeline.EgressAuthMeta])
	_ = json.Unmarshal(raw, &auth)
	u, err := url.Parse(target)
	if err != nil {
		return "error " + err.Error()
	}
	proxy, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxy.Host == "" {
		return "error no proxy"
	}
	method, body := http.MethodGet, io.Reader(nil)
	if n > 0 {
		method, body = http.MethodPost, strings.NewReader(strings.Repeat("x", n))
	}
	req, _ := http.NewRequest(method, target, body)
	req.Header.Set(auth.Header, auth.Take(u.Hostname(), port))
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	resp, err := c.Do(req)
	if err != nil {
		return "error " + err.Error()
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return fmt.Sprintf("%d %s", resp.StatusCode, resp.Header.Get(egress.ReasonHeader))
}

// TestEgressLimitObligationEndToEnd is FR-5.38's decision-obligation
// source through the whole Gateway: a permit rule's egress_limits travel
// with the decision into the call's one-use egress capabilities, and the
// Egress Broker bounds the operations the backend makes while serving the
// call by them, below the larger [egress] limits and grant. A request
// body, a response body and a duration above the rule's bounds are each
// refused with their reason code and journaled; the record of an allowed
// operation names the call's decision and the bounds applied. The same
// tool under a rule without egress_limits gets the configuration's bounds.
func TestEgressLimitObligationEndToEnd(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Length", "4096")
			w.Write(make([]byte, 4096))
		case "/slow":
			time.Sleep(900 * time.Millisecond)
			io.WriteString(w, "late")
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer dest.Close()
	port := dest.Listener.Addr().(*net.TCPAddr).Port
	f := start(t, `
[egress]
enabled = true
request_bytes = 100000
response_bytes = 100000
operation_timeout = "10s"
[[egress.grant]]
server = "t"
host = "127.0.0.1"
ports = [`+strconv.Itoa(port)+`]
methods = ["GET", "POST"]
addresses = ["127.0.0.1"]
`)
	limited := strings.Replace(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1),
		`{"id": "ro-approve"`, `{"id": "ro-egress", "server": "t", "tools": ["egress_get"], "egress_limits": {"request_bytes": 1000, "response_bytes": 2000, "timeout_ms": 300}},
                     {"id": "ro-approve"`, 1)
	f.publish(limited)
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	fetch := func(path string, body int) string {
		t.Helper()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_egress_get", Arguments: map[string]any{"port": port, "path": path, "body": body}})
		if err != nil || res.IsError {
			t.Fatalf("t_egress_get %s: %v %+v", path, err, res)
		}
		return res.Content[0].(*mcp.TextContent).Text
	}
	if got := fetch("/", 0); got != "200 " {
		t.Fatalf("small request: %q", got)
	}
	rec := f.app.Egress.Recent()[0]
	if rec.Bounds == nil || *rec.Bounds != (egress.Bounds{RequestBytes: 1000, ResponseBytes: 2000, TimeoutMS: 300}) || rec.DecisionID == "" {
		t.Fatalf("record %+v bounds %+v", rec, rec.Bounds)
	}
	for _, c := range []struct {
		path, want string
		body       int
	}{
		{"/", "413 " + egress.ReasonRequestTooLarge, 1500},
		{"/big", "502 " + egress.ReasonResponseTooLarge, 0},
		{"/slow", "504 " + egress.ReasonTimeout, 0},
	} {
		if got := fetch(c.path, c.body); got != c.want {
			t.Fatalf("%s body %d: %q, want %q", c.path, c.body, got, c.want)
		}
	}
	// Each refusal is journaled with its reason and the decision whose
	// obligation applied.
	evs := journalEvents(t, f.stateDir)
	for _, reason := range []string{egress.ReasonRequestTooLarge, egress.ReasonResponseTooLarge, egress.ReasonTimeout} {
		found := false
		for _, e := range evs {
			if e.Origin == egress.Origin && e.ReasonCode == reason && e.DecisionID != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("no journaled egress event with %s and a decision ID", reason)
		}
	}
	// The decision record carries the obligation.
	found := false
	for _, e := range evs {
		if e.Class != "decision" || e.DecisionID != rec.DecisionID {
			continue
		}
		d, _ := e.Detail.(map[string]any)
		ob, _ := d["obligations"].(map[string]any)
		if el, _ := ob["egress_limits"].(map[string]any); el["request_bytes"] == float64(1000) && el["response_bytes"] == float64(2000) && el["timeout_ms"] == float64(300) {
			found = true
		}
	}
	if !found {
		t.Error("no decision record with the egress_limits obligation")
	}

	// Without the rule's limits the configuration's bounds apply.
	f.publish(strings.Replace(strings.Replace(limited, `"r2"`, `"r3"`, 1),
		`, "egress_limits": {"request_bytes": 1000, "response_bytes": 2000, "timeout_ms": 300}`, ``, 1))
	if got := fetch("/big", 1500); got != "200 " {
		t.Fatalf("configuration bounds: %q", got)
	}
	if rec := f.app.Egress.Recent()[0]; rec.Bounds == nil || *rec.Bounds != (egress.Bounds{RequestBytes: 100000, ResponseBytes: 100000, TimeoutMS: 10000}) {
		t.Fatalf("configuration bounds record %+v", rec.Bounds)
	}
}
