package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// rawMsg is one JSON-RPC message a scripted server received.
type rawMsg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// rawServer is a scripted stdio MCP server that speaks newline-delimited
// JSON-RPC itself, so tests can send what an SDK server never would. It
// answers initialize, ping and tools/list (in pages of one tool when
// paged), records every line it receives, and hands tools/call to call.
type rawServer struct {
	tools []string
	paged bool
	// call handles tools/call; it writes zero or more lines with w. It
	// returns false to end the server (the process exits).
	call func(w func(string), id json.RawMessage, name string, params json.RawMessage) bool

	mu    sync.Mutex
	lines [][]byte // every line received, across instances
	calls atomic.Int32
}

func (rs *rawServer) received() [][]byte {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([][]byte(nil), rs.lines...)
}

func (rs *rawServer) methods() []string {
	var out []string
	for _, l := range rs.received() {
		var m rawMsg
		_ = json.Unmarshal(l, &m)
		out = append(out, m.Method)
	}
	return out
}

func (rs *rawServer) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	var wmu sync.Mutex
	w := func(s string) {
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = io.WriteString(out, s+"\n")
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		rs.mu.Lock()
		rs.lines = append(rs.lines, line)
		rs.mu.Unlock()
		var m rawMsg
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(m.Params, &p)
			w(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q,"capabilities":{"tools":{}},"serverInfo":{"name":"raw","version":"1"}}}`, m.ID, p.ProtocolVersion))
		case "ping":
			w(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, m.ID))
		case "tools/list":
			var p struct {
				Cursor string `json:"cursor"`
			}
			_ = json.Unmarshal(m.Params, &p)
			names, next := rs.tools, ""
			if rs.paged {
				i := 0
				if p.Cursor != "" {
					fmt.Sscanf(p.Cursor, "page-%d", &i)
				}
				names = rs.tools[i : i+1]
				if i+1 < len(rs.tools) {
					next = fmt.Sprintf("page-%d", i+1)
				}
			}
			var ts []string
			for _, n := range names {
				ts = append(ts, fmt.Sprintf(`{"name":%q,"inputSchema":{"type":"object"}}`, n))
			}
			res := `{"tools":[` + strings.Join(ts, ",") + `]`
			if next != "" {
				res += fmt.Sprintf(`,"nextCursor":%q`, next)
			}
			w(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}}`, m.ID, res))
		case "tools/call":
			rs.calls.Add(1)
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(m.Params, &p)
			if rs.call != nil && !rs.call(w, m.ID, p.Name, m.Params) {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return sc.Err()
}

// rawLauncher counts launches of a rawServer.
type rawLauncher struct {
	rs       *rawServer
	launches atomic.Int32
	mu       sync.Mutex
	procs    []pipeline.Process
}

func (*rawLauncher) Name() string   { return "raw" }
func (*rawLauncher) Confined() bool { return false }
func (l *rawLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	l.launches.Add(1)
	p, err := pipeline.InProcessLauncher{Raw: map[string]func(context.Context, io.Reader, io.Writer) error{spec.Command: l.rs.serve}}.Launch(ctx, spec)
	if err == nil {
		l.mu.Lock()
		l.procs = append(l.procs, p)
		l.mu.Unlock()
	}
	return p, err
}

func startRaw(t *testing.T, rs *rawServer, timeout time.Duration, manifests pipeline.ManifestSource) (*Registry, *pipeline.Capabilities, *rawLauncher) {
	t.Helper()
	if rs.tools == nil {
		rs.tools = []string{"act"}
	}
	caps := pipeline.NewCapabilities(time.Minute)
	l := &rawLauncher{rs: rs}
	r, err := Start(context.Background(), []config.Server{{Alias: "r", Command: "/raw"}}, Options{
		Limits:   Limits{PerPrincipal: 4, Total: 4, Queue: 4, UpstreamTimeout: timeout, ResultBytes: 1 << 20},
		Launcher: l, Capabilities: caps, Manifests: manifests})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r, caps, l
}

func textResult(id json.RawMessage, text string) string {
	b, _ := json.Marshal(text)
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":%s}]}}`, id, b)
}

// TestLegacyHandshake: the dispatcher sends initialize with protocol
// version 2025-11-25, empty capabilities and the Gateway's clientInfo, then
// notifications/initialized, before any other request (FR-5.19).
func TestLegacyHandshake(t *testing.T) {
	reqtest.Verifies(t, "FR-5.19")
	rs := &rawServer{}
	r, _, _ := startRaw(t, rs, 5*time.Second, nil)
	lines := rs.received()
	if len(lines) < 3 {
		t.Fatalf("received %q", lines)
	}
	var init struct {
		Method string `json:"method"`
		Params struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    json.RawMessage `json:"capabilities"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		} `json:"params"`
	}
	if err := json.Unmarshal(lines[0], &init); err != nil {
		t.Fatal(err)
	}
	if init.Method != "initialize" || init.Params.ProtocolVersion != "2025-11-25" || string(init.Params.Capabilities) != "{}" ||
		init.Params.ClientInfo.Name != "secure-mcp-gateway" || init.Params.ClientInfo.Version != Version {
		t.Fatalf("initialize %s", lines[0])
	}
	m := rs.methods()
	if m[1] != "notifications/initialized" || m[2] != "tools/list" {
		t.Fatalf("sequence %v", m)
	}
	if s := r.Servers()["r"]; s.Era != "2025-11-25" {
		t.Fatalf("negotiated era %q", s.Era)
	}
}

// TestStdioFraming: every message the dispatcher writes is one line of
// UTF-8 JSON-RPC; in the other direction a single-line UTF-8 response is
// accepted, and a line with invalid UTF-8 or a message split over two lines
// fails the call (FR-5.13).
func TestStdioFraming(t *testing.T) {
	reqtest.Verifies(t, "FR-5.13")
	mode := atomic.Value{}
	mode.Store("ok")
	rs := &rawServer{call: func(w func(string), id json.RawMessage, _ string, _ json.RawMessage) bool {
		switch mode.Load().(string) {
		case "ok":
			w(textResult(id, "héllo ✓   line"))
		case "badutf8":
			w(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"content":[{"type":"text","text":"` + "\xff\xfe" + `"}]}}`)
		case "split":
			w(`{"jsonrpc":"2.0","id":` + string(id) + `,`)
			w(`"result":{"content":[]}}`)
		}
		return true
	}}
	r, caps, _ := startRaw(t, rs, 5*time.Second, nil)
	res, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), "c1", `{"text":"ünïcode\nwith newline"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content[0].(*mcp.TextContent).Text; got != "héllo ✓   line" {
		t.Fatalf("text %q", got)
	}
	for _, l := range rs.received() {
		var m map[string]any
		if !utf8.Valid(l) || json.Unmarshal(l, &m) != nil || m["jsonrpc"] != "2.0" || strings.ContainsRune(string(l), '\n') {
			t.Fatalf("southbound line %q", l)
		}
	}
	for i, m := range []string{"badutf8", "split"} {
		mode.Store(m)
		if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), fmt.Sprintf("c%d", i+2), `{}`)); !errors.Is(err, ErrInvalidOutput) {
			t.Fatalf("%s: got %v", m, err)
		}
	}
}

// TestInvalidStdoutLine: a non-JSON stdout line fails the in-flight call
// and the instance is terminated and replaced (FR-5.14; the edge maps the
// error to -31007, see internal/edge TestBackendProtocolFailures).
func TestInvalidStdoutLine(t *testing.T) {
	reqtest.Partial(t, "FR-5.14")
	bad := atomic.Bool{}
	bad.Store(true)
	rs := &rawServer{call: func(w func(string), id json.RawMessage, _ string, _ json.RawMessage) bool {
		if bad.Swap(false) {
			w("Starting server... this is a log line on stdout")
			return true
		}
		w(textResult(id, "ok"))
		return true
	}}
	r, caps, l := startRaw(t, rs, 5*time.Second, nil)
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), "c1", `{}`)); !errors.Is(err, ErrInvalidOutput) {
		t.Fatalf("got %v", err)
	}
	res, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), "c2", `{}`))
	if err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if res.Content[0].(*mcp.TextContent).Text != "ok" || l.launches.Load() != 2 || r.Servers()["r"].Restarts() != 1 {
		t.Fatalf("launches %d restarts %d", l.launches.Load(), r.Servers()["r"].Restarts())
	}
	// The first instance is gone: writing to it fails.
	l.mu.Lock()
	first := l.procs[0]
	l.mu.Unlock()
	if _, err := first.Write([]byte("{}\n")); err == nil {
		t.Fatal("the first instance still accepts input")
	}
}

// TestResultTypeHandling: a result without resultType is complete, a
// "complete" result is complete, and an unrecognized resultType is an
// invalid result (FR-5.23).
func TestResultTypeHandling(t *testing.T) {
	reqtest.Verifies(t, "FR-5.23")
	kind := atomic.Value{}
	rs := &rawServer{call: func(w func(string), id json.RawMessage, _ string, _ json.RawMessage) bool {
		switch kind.Load().(string) {
		case "none":
			w(textResult(id, "none"))
		case "complete":
			w(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"resultType":"complete","content":[{"type":"text","text":"complete"}]}}`)
		case "unknown":
			w(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"resultType":"partial","content":[{"type":"text","text":"unknown"}]}}`)
		}
		return true
	}}
	r, caps, _ := startRaw(t, rs, 5*time.Second, nil)
	for i, k := range []string{"none", "complete", "unknown", "none"} {
		kind.Store(k)
		res, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), fmt.Sprintf("c%d", i), `{}`))
		if k == "unknown" {
			if !errors.Is(err, ErrInvalidResult) || res != nil {
				t.Fatalf("unknown resultType: %v %v", res, err)
			}
			continue
		}
		if err != nil || res.Content[0].(*mcp.TextContent).Text != k {
			t.Fatalf("%s: %v %v", k, res, err)
		}
	}
}

// TestSouthboundCancellation: cancelling a dispatched call sends
// notifications/cancelled with the call's request ID to the stdio instance
// (FR-5.26).
func TestSouthboundCancellation(t *testing.T) {
	reqtest.Verifies(t, "FR-5.26")
	got := make(chan json.RawMessage, 1)
	rs := &rawServer{call: func(_ func(string), id json.RawMessage, _ string, _ json.RawMessage) bool {
		got <- id
		return true // never answers
	}}
	r, caps, _ := startRaw(t, rs, 30*time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := r.Call(ctx, dispatch(caps, r.Resolve("r_act"), "c1", `{}`))
		errc <- err
	}()
	id := <-got
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if !waitCancelled(rs, id, 5*time.Second) {
		t.Fatalf("no notifications/cancelled for %s; received %v", id, rs.methods())
	}
}

// waitCancelled waits until the server received notifications/cancelled
// naming id.
func waitCancelled(rs *rawServer, id json.RawMessage, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, l := range rs.received() {
			var m struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			if json.Unmarshal(l, &m) == nil && m.Method == "notifications/cancelled" && string(m.Params.RequestID) == string(id) {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestProgressTokensUnique: concurrent progress-enabled calls carry
// distinct Gateway-generated progress tokens southbound (FR-5.32).
func TestProgressTokensUnique(t *testing.T) {
	reqtest.Verifies(t, "FR-5.32")
	var mu sync.Mutex
	tokens := map[string]int{}
	release := make(chan struct{})
	rs := &rawServer{call: func(w func(string), id json.RawMessage, _ string, params json.RawMessage) bool {
		var p struct {
			Meta struct {
				ProgressToken any `json:"progressToken"`
			} `json:"_meta"`
		}
		_ = json.Unmarshal(params, &p)
		mu.Lock()
		tokens[fmt.Sprint(p.Meta.ProgressToken)]++
		mu.Unlock()
		go func() { <-release; w(textResult(id, "ok")) }()
		return true
	}}
	r, caps, _ := startRaw(t, rs, 10*time.Second, nil)
	const n = 4
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := dispatch(caps, r.Resolve("r_act"), fmt.Sprintf("c%d", i), `{}`)
			d.Progress = func(*mcp.ProgressNotificationParams) {}
			if _, err := r.Call(context.Background(), d); err != nil {
				t.Error(err)
			}
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for rs.calls.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(tokens) != n {
		t.Fatalf("tokens %v", tokens)
	}
	for tok, c := range tokens {
		if c != 1 || !strings.HasPrefix(tok, "smcp-") {
			t.Fatalf("tokens %v", tokens)
		}
	}
}

// countingManifests records the live tool list the dispatcher hands to the
// ManifestSource.
type countingManifests struct{ got []string }

func (c *countingManifests) Tools(ctx context.Context, spec pipeline.ServerSpec, live pipeline.LiveLister) (pipeline.ToolSet, error) {
	ts, err := pipeline.LiveManifest{}.Tools(ctx, spec, live)
	for _, t := range ts.Tools {
		c.got = append(c.got, t.Name)
	}
	return ts, err
}

// TestPagedToolList: the dispatcher reads every page of tools/list at
// start and passes the complete list to the ManifestSource (FR-5.21).
func TestPagedToolList(t *testing.T) {
	reqtest.Verifies(t, "FR-5.21")
	rs := &rawServer{tools: []string{"one", "two", "three"}, paged: true}
	cm := &countingManifests{}
	r, _, _ := startRaw(t, rs, 5*time.Second, cm)
	if sort.Strings(cm.got); strings.Join(cm.got, ",") != "one,three,two" {
		t.Fatalf("manifest source saw %v", cm.got)
	}
	if got := strings.Join(r.PublicNames(), ","); got != "r_one,r_three,r_two" {
		t.Fatalf("catalog %s", got)
	}
	lists := 0
	for _, m := range rs.methods() {
		if m == "tools/list" {
			lists++
		}
	}
	if lists != 3 {
		t.Fatalf("tools/list requests %d", lists)
	}
}

// TestResponseValidation: a malformed CallToolResult is withheld as an
// invalid result, a response with another request ID is never delivered to
// the call, and a message without the JSON-RPC envelope fails the call
// (SR-5.20-1; the edge side is TestBackendProtocolFailures).
func TestResponseValidation(t *testing.T) {
	reqtest.Partial(t, "SR-5.20-1")
	kind := atomic.Value{}
	rs := &rawServer{call: func(w func(string), id json.RawMessage, _ string, _ json.RawMessage) bool {
		switch kind.Load().(string) {
		case "result":
			w(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"content":"not an array"}}`)
		case "id":
			w(`{"jsonrpc":"2.0","id":987654,"result":{"content":[{"type":"text","text":"stray"}]}}`)
		case "envelope":
			w(`{"id":` + string(id) + `,"result":{"content":[]}}`)
		}
		return true
	}}
	r, caps, _ := startRaw(t, rs, 500*time.Millisecond, nil)
	for i, tc := range []struct {
		kind string
		want error
	}{{"result", ErrInvalidResult}, {"id", ErrTimeout}, {"envelope", ErrInvalidOutput}} {
		kind.Store(tc.kind)
		res, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), fmt.Sprintf("c%d", i), `{}`))
		if !errors.Is(err, tc.want) || res != nil {
			t.Fatalf("%s: %v %v", tc.kind, res, err)
		}
	}
}

// TestInstanceFailureNotRetried: an instance that exits after receiving a
// call fails the call with ErrInstanceFailed; the call is not sent again
// to the replacement instance (SR-7.2-1; the edge records it as
// indeterminate for write-class tools).
func TestInstanceFailureNotRetried(t *testing.T) {
	reqtest.Partial(t, "SR-7.2-1")
	rs := &rawServer{call: func(func(string), json.RawMessage, string, json.RawMessage) bool {
		return false // the process exits without answering
	}}
	r, caps, l := startRaw(t, rs, 5*time.Second, nil)
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("r_act"), "c1", `{}`)); !errors.Is(err, ErrInstanceFailed) {
		t.Fatalf("got %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for l.launches.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if rs.calls.Load() != 1 {
		t.Fatalf("tools/call sent %d times", rs.calls.Load())
	}
}
