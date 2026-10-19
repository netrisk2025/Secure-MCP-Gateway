package backend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestPublicName(t *testing.T) {
	reqtest.Verifies(t, "FR-1.26")
	cases := map[[2]string]string{
		{"a", "search"}:        "a_search",
		{"b", "search"}:        "b_search",
		{"c", "files.read"}:    "c_files_read",
		{"c", "get-user info"}: "c_get_user_info",
	}
	for in, want := range cases {
		if got := PublicName(in[0], in[1]); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
	if PublicName("c", "a.b") != PublicName("c", "a_b") {
		t.Fatal("sanitized names must collide so FR-1.49 can detect them")
	}
}

func TestCheckToolDefinition(t *testing.T) {
	// Unit checks; the drift handling of every defect is TestToolDefinitionDriftHandling.
	reqtest.Partial(t, "FR-5.22")
	ok := &mcp.Tool{Name: "x", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"file.path-1": map[string]any{"type": "string"}}}}
	if err := CheckToolDefinition(ok); err != nil {
		t.Fatal(err)
	}
	long := &mcp.Tool{Name: "x", InputSchema: map[string]any{"type": "object", "properties": map[string]any{strings.Repeat("p", 65): map[string]any{}}}}
	if err := CheckToolDefinition(long); err == nil {
		t.Error("65-character property accepted")
	}
	space := &mcp.Tool{Name: "x", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"has space": map[string]any{}}}}
	if err := CheckToolDefinition(space); err == nil {
		t.Error("property with a space accepted")
	}
	if err := CheckToolDefinition(&mcp.Tool{Name: "x"}); err == nil {
		t.Error("null inputSchema accepted")
	}
}

// memLauncher runs an in-process MCP server over pipes, so dispatcher tests
// need no subprocess.
type memLauncher struct {
	confined bool
	build    func() *mcp.Server
}

func (memLauncher) Name() string     { return "memory" }
func (l memLauncher) Confined() bool { return l.confined }

type memProc struct {
	io.Reader
	io.Writer
	closers []io.Closer
	cancel  context.CancelFunc
	once    sync.Once
}

func (p *memProc) Close() error {
	p.once.Do(func() {
		for _, c := range p.closers {
			c.Close()
		}
		p.cancel()
	})
	return nil
}
func (p *memProc) Stderr() string { return "" }

func (l memLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	toSrvR, toSrvW := io.Pipe()
	fromSrvR, fromSrvW := io.Pipe()
	sctx, cancel := context.WithCancel(context.Background())
	srv := l.build()
	go srv.Run(sctx, &mcp.IOTransport{Reader: toSrvR, Writer: fromSrvW})
	return &memProc{Reader: fromSrvR, Writer: toSrvW, closers: []io.Closer{toSrvW, fromSrvR, toSrvR, fromSrvW}, cancel: cancel}, nil
}

func testServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "mem", Version: "1"}, nil)
	type textArgs struct {
		Text string `json:"text"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(ctx context.Context, req *mcp.CallToolRequest, a textArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: a.Text}}}, nil, nil
	})
	type bigArgs struct {
		KiB int `json:"kib"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "big"}, func(ctx context.Context, req *mcp.CallToolRequest, a bigArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", a.KiB*1024)}}}, nil, nil
	})
	type deepArgs struct {
		Levels int `json:"levels"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "deep"}, func(ctx context.Context, req *mcp.CallToolRequest, a deepArgs) (*mcp.CallToolResult, any, error) {
		v := map[string]any{}
		for range a.Levels {
			v = map[string]any{"a": v}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deep"}}, StructuredContent: v}, nil, nil
	})
	type sleepArgs struct {
		MS int `json:"ms"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "sleep"}, func(ctx context.Context, req *mcp.CallToolRequest, a sleepArgs) (*mcp.CallToolResult, any, error) {
		select {
		case <-time.After(time.Duration(a.MS) * time.Millisecond):
		case <-ctx.Done():
		}
		return &mcp.CallToolResult{}, nil, nil
	})
	return s
}

func startRegistry(t *testing.T, limits Limits, caps *pipeline.Capabilities) *Registry {
	t.Helper()
	if limits.UpstreamTimeout == 0 {
		limits.UpstreamTimeout = 5 * time.Second
	}
	if limits.ResultBytes == 0 {
		limits.ResultBytes = 64 << 10
	}
	r, err := Start(context.Background(), []config.Server{{Alias: "m", Command: "/fake/mem"}},
		Options{Limits: limits, Launcher: memLauncher{build: testServer}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func dispatch(caps *pipeline.Capabilities, ref *ToolRef, corr string, args string) Dispatch {
	b := pipeline.Binding{CorrelationID: corr, DecisionID: "d-" + corr, PolicyRevision: "r1", PublicName: ref.Public}
	return Dispatch{Principal: "p", Ref: ref, Arguments: json.RawMessage(args), Capability: caps.Issue(b), Binding: b}
}

func TestDispatcherRequiresCapability(t *testing.T) {
	reqtest.Verifies(t, "FR-4.13")
	caps := pipeline.NewCapabilities(time.Minute)
	r := startRegistry(t, Limits{PerPrincipal: 2, Total: 2, Queue: 2}, caps)
	ref := r.Resolve("m_echo")
	if ref == nil || r.Servers()["m"].Verified || r.Servers()["m"].ManifestSource != "live" {
		t.Fatal("echo not indexed or wrongly verified")
	}
	ctx := context.Background()
	// No capability.
	d := dispatch(caps, ref, "c1", `{"text":"a"}`)
	noCap := d
	noCap.Capability = ""
	if _, err := r.Call(ctx, noCap); !errors.Is(err, pipeline.ErrNoCapability) {
		t.Fatalf("no capability: %v", err)
	}
	// Valid capability, then reuse.
	res, err := r.Call(ctx, d)
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "a" {
		t.Fatalf("%v %v", res, err)
	}
	if _, err := r.Call(ctx, d); !errors.Is(err, pipeline.ErrCapabilityUsed) {
		t.Fatalf("reuse: %v", err)
	}
	// A capability from another call.
	other := dispatch(caps, ref, "c2", `{"text":"b"}`)
	stolen := dispatch(caps, ref, "c3", `{"text":"c"}`)
	stolen.Capability = other.Capability
	if _, err := r.Call(ctx, stolen); !errors.Is(err, pipeline.ErrCapabilityMismatch) {
		t.Fatalf("other call's capability: %v", err)
	}
	// A capability bound to another tool cannot dispatch this one.
	wrongTool := dispatch(caps, r.Resolve("m_big"), "c4", `{}`)
	wrongTool.Ref = ref
	if _, err := r.Call(ctx, wrongTool); !errors.Is(err, pipeline.ErrCapabilityMismatch) {
		t.Fatalf("other tool: %v", err)
	}
}

func TestResultBoundWhileReading(t *testing.T) {
	// The boundaries of FR-4.10 (size and depth) are TestResultBoundsAtTheLimit.
	reqtest.Partial(t, "FR-4.10")
	caps := pipeline.NewCapabilities(time.Minute)
	r := startRegistry(t, Limits{PerPrincipal: 2, Total: 2, Queue: 2, ResultBytes: 16 << 10}, caps)
	big := r.Resolve("m_big")
	// 256 KiB exceeds 16 KiB + envelope: the line is cut while reading and
	// replaced by an error for the same request.
	if _, err := r.Call(context.Background(), dispatch(caps, big, "c1", `{"kib":256}`)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if r.Servers()["m"].OversizedFrames() != 1 {
		t.Fatal("oversized frame not counted")
	}
	// 32 KiB passes the frame bound but not the decoded-size check.
	if _, err := r.Call(context.Background(), dispatch(caps, big, "c2", `{"kib":32}`)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	// The connection survives: a small call still works.
	if _, err := r.Call(context.Background(), dispatch(caps, big, "c3", `{"kib":1}`)); err != nil {
		t.Fatal(err)
	}
}

func TestFrameFilter(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":7,"result":{"x":"` + strings.Repeat("y", 100) + `"}}` + "\n" +
		`{"jsonrpc":"2.0","result":{"x":"` + strings.Repeat("y", 100) + `"},"id":8}` + "\n" +
		`{"jsonrpc":"2.0","id":9,"result":{}}` + "\n"
	f := newFrameFilter(strings.NewReader(in), 60)
	out, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"id":7`) || !strings.Contains(lines[0], tooLargeMessage) || lines[1] != `{"jsonrpc":"2.0","id":9,"result":{}}` {
		t.Fatalf("%q", lines)
	}
	if f.oversized.Load() != 2 {
		t.Fatalf("oversized %d", f.oversized.Load())
	}
}

func TestQueueBoundIsAtomicAndFIFO(t *testing.T) {
	reqtest.Verifies(t, "FR-4.8")
	caps := pipeline.NewCapabilities(time.Minute)
	r := startRegistry(t, Limits{PerPrincipal: 1, Total: 1, Queue: 2}, caps)
	sleep := r.Resolve("m_sleep")
	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	full, ok := 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		d := dispatch(caps, sleep, "q"+string(rune('a'+i)), `{"ms":150}`)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := r.Call(context.Background(), d)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, ErrQueueFull):
				full++
			case err == nil:
				ok++
			default:
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	// One runs, at most two wait; everything else is refused.
	if ok > 3 || ok < 1 || full != n-ok {
		t.Fatalf("ok=%d full=%d", ok, full)
	}
	if r.Waiting() != 0 {
		t.Fatalf("waiting counter leaked: %d", r.Waiting())
	}
	// Queue 0: nobody waits, but a free slot is still used.
	r0 := startRegistry(t, Limits{PerPrincipal: 1, Total: 1, Queue: 0}, caps)
	if _, err := r0.Call(context.Background(), dispatch(caps, r0.Resolve("m_echo"), "z", `{"text":"x"}`)); err != nil {
		t.Fatalf("queue 0 refused an idle dispatcher: %v", err)
	}
	// FIFO order of grants.
	f := newFIFO(1)
	if !f.tryAcquire() {
		t.Fatal("fresh fifo")
	}
	order := make(chan int, 3)
	var wg2 sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			f.acquire(context.Background())
			order <- i
			f.release()
		}(i)
		for {
			f.mu.Lock()
			l := f.waiters.Len()
			f.mu.Unlock()
			if l == i+1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	if f.tryAcquire() {
		t.Fatal("newcomer overtook the queue")
	}
	f.release()
	wg2.Wait()
	close(order)
	want := 0
	for got := range order {
		if got != want {
			t.Fatalf("grant order: got %d want %d", got, want)
		}
		want++
	}
	// A cancelled waiter leaves the queue.
	g := newFIFO(1)
	g.tryAcquire()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.acquire(ctx); err == nil {
		t.Fatal("acquired a busy slot")
	}
	if g.waiters.Len() != 0 {
		t.Fatal("cancelled waiter left in queue")
	}
}

func TestUpstreamTimeout(t *testing.T) {
	reqtest.Verifies(t, "FR-4.9")
	caps := pipeline.NewCapabilities(time.Minute)
	r := startRegistry(t, Limits{PerPrincipal: 1, Total: 1, Queue: 1, UpstreamTimeout: 100 * time.Millisecond}, caps)
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("m_sleep"), "t", `{"ms":2000}`)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestHighRiskRefusedWhenUnconfined(t *testing.T) {
	caps := pipeline.NewCapabilities(time.Minute)
	servers := []config.Server{{Alias: "x", Command: "/fake/x", RiskClasses: []string{"code-execution"}}}
	if _, err := Start(context.Background(), servers, Options{Limits: Limits{PerPrincipal: 1, Total: 1}, Launcher: memLauncher{build: testServer}, Capabilities: caps}); !errors.Is(err, ErrHighRiskUnconfined) {
		t.Fatalf("got %v", err)
	}
	r, err := Start(context.Background(), servers, Options{Limits: Limits{PerPrincipal: 1, Total: 1, ResultBytes: 1 << 20, UpstreamTimeout: time.Second}, Launcher: memLauncher{confined: true, build: testServer}, Capabilities: caps})
	if err != nil {
		t.Fatalf("confined launcher refused: %v", err)
	}
	r.Close()
	// Secrets without a broker refuse the launch.
	sec := []config.Server{{Alias: "s", Command: "/fake/s", SecretEnv: map[string]string{"TOKEN": "vault:t"}}}
	if _, err := Start(context.Background(), sec, Options{Limits: Limits{PerPrincipal: 1, Total: 1}, Launcher: memLauncher{build: testServer}, Capabilities: caps}); !errors.Is(err, pipeline.ErrNoSecretBroker) {
		t.Fatalf("got %v", err)
	}
	// npx is refused before launch.
	npx := []config.Server{{Alias: "n", Command: "npx"}}
	if _, err := Start(context.Background(), npx, Options{Limits: Limits{PerPrincipal: 1, Total: 1}, Launcher: memLauncher{build: testServer}, Capabilities: caps}); !errors.Is(err, pipeline.ErrUnpinnedLaunch) {
		t.Fatalf("got %v", err)
	}
}
