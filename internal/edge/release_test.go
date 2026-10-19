package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// gateFilter holds the three-part result until open is closed, reporting
// on entered when it has it. Progress messages, which the response filters
// also inspect, pass.
type gateFilter struct {
	entered chan<- struct{}
	open    <-chan struct{}
}

func (gateFilter) ID() string { return "release-gate" }
func (g gateFilter) FilterResponse(ctx context.Context, c *pipeline.Call, r *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	if len(r.Content) != 3 {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil // a progress message under inspection
	}
	g.entered <- struct{}{}
	select {
	case <-g.open:
	case <-ctx.Done():
	}
	return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
}

const releasePolicy = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
  "templates": {"ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["parts"]}]}}
}`

// partsBackend's parts tool reports progress twice, waits, and returns a
// three-part result.
func partsBackend() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "parts-backend", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "parts"}, func(ctx context.Context, req *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
		if tok := req.Params.GetProgressToken(); tok != nil {
			for i := 1; i <= 2; i++ {
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: float64(i), Message: "working"})
				time.Sleep(20 * time.Millisecond)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "PART-1"}, &mcp.TextContent{Text: "PART-2"}, &mcp.TextContent{Text: "PART-3"}}}, nil, nil
	})
	return s
}

// wireRead is a response read as it arrives.
type wireRead struct {
	mu      sync.Mutex
	headers bool
	body    bytes.Buffer
	// releasedFirst is set when the first result byte arrived after the
	// call's delivered event was committed.
	releasedFirst, sawResult bool
	done                     chan struct{}
}

func (w *wireRead) snapshot() (bool, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.headers, w.body.String()
}

// TestNoResultBeforeRelease: while the complete backend result waits in
// the response inspection, nothing of it reaches the harness — not even
// response headers for a plain request, and only the (inspected) progress
// notifications for a request with a progress token; the result's parts
// arrive only after the release authorization (the delivered event) is
// committed (SR-5.11-1). Progress notifications are relayed by FR-1.39 and
// are not result content.
func TestNoResultBeforeRelease(t *testing.T) {
	reqtest.Verifies(t, "SR-5.11-1")
	entered, open := make(chan struct{}, 4), make(chan struct{})
	f := pipeline.NewFilters()
	if err := f.RegisterResponse(gateFilter{entered: entered, open: open}, pipeline.Registration{Order: 10, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOpts{filters: f, backend: partsBackend, policy: releasePolicy, limits: "principal_calls_per_minute = 1000"})
	_, tok := h.session("ro")
	delivered := func() bool {
		return h.rec.find(func(e audit.Event) bool { return e.Class == "call" && e.Phase == audit.PhaseDelivered }) != nil
	}

	start := func(id int, meta string) *wireRead {
		w := &wireRead{done: make(chan struct{})}
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"t_parts","arguments":{},"_meta":{%s%s}}}`, id, meta, wireMeta)
		req, err := http.NewRequest("POST", h.srv.URL+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		hdr := wireHeaders(tok, "tools/call")
		hdr["Mcp-Name"] = "t_parts"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		go func() {
			defer close(w.done)
			r, err := h.srv.Client().Do(req)
			if err != nil {
				return
			}
			defer r.Body.Close()
			w.mu.Lock()
			w.headers = true
			w.mu.Unlock()
			buf := make([]byte, 512)
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					rel := delivered()
					w.mu.Lock()
					w.body.Write(buf[:n])
					if !w.sawResult && strings.Contains(w.body.String(), "PART-") {
						w.sawResult, w.releasedFirst = true, rel
					}
					w.mu.Unlock()
				}
				if err == io.EOF || err != nil {
					return
				}
			}
		}()
		return w
	}
	waitEntered := func(w *wireRead) {
		select {
		case <-w.done:
			_, body := w.snapshot()
			t.Fatalf("the call ended before the response inspection: %q", body)
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("the result never reached the response inspection: %v", h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseDenied || e.Phase == audit.PhaseFailed }))
		}
		time.Sleep(300 * time.Millisecond) // anything sent early would arrive now
	}

	// A plain request: the response is held whole, headers included.
	plain := start(7, "")
	waitEntered(plain)
	if hdr, body := plain.snapshot(); hdr || body != "" || delivered() {
		t.Fatalf("before release: headers %v, body %q, delivered %v", hdr, body, delivered())
	}

	// A request with a progress token, made by an SDK client while the
	// first call waits: every byte of its responses is recorded as it
	// arrives. The stream may carry progress, never result content.
	streamed := &wireRead{done: make(chan struct{})}
	var progress sync.Mutex
	var relayed []string
	hc := h.srv.Client()
	hc.Transport = teeRT{base: bearerRT{tok, hc.Transport}, w: streamed, delivered: delivered}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "release-test", Version: "1"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
			progress.Lock()
			relayed = append(relayed, r.Params.Message)
			progress.Unlock()
		}}).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: h.srv.URL + "/mcp", HTTPClient: hc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	go func() {
		defer close(streamed.done)
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_parts", Meta: mcp.Meta{"progressToken": "p1"}})
		if err != nil || len(res.Content) != 3 {
			t.Errorf("streamed call: %v %+v", err, res)
		}
	}()
	waitEntered(streamed)
	_, body := streamed.snapshot()
	if strings.Contains(body, "PART-") {
		t.Fatalf("result content before release: %q", body)
	}
	progress.Lock()
	n := len(relayed)
	progress.Unlock()
	if n == 0 || !strings.Contains(body, "working") {
		t.Fatalf("progress was not relayed while the result was held (%d notifications): %q", n, body)
	}

	close(open)
	for _, w := range []*wireRead{plain, streamed} {
		select {
		case <-w.done:
		case <-time.After(10 * time.Second):
			t.Fatal("response never completed")
		}
		_, body := w.snapshot()
		for _, part := range []string{"PART-1", "PART-2", "PART-3"} {
			if !strings.Contains(body, part) {
				t.Fatalf("released result lacks %s: %q", part, body)
			}
		}
		if !w.releasedFirst {
			t.Fatalf("result content arrived before the delivered event was committed: %q", body)
		}
	}
}

// teeRT records every response body byte in w as the client reads it.
type teeRT struct {
	base      http.RoundTripper
	w         *wireRead
	delivered func() bool
}

func (t teeRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err == nil {
		resp.Body = teeBody{ReadCloser: resp.Body, t: t}
	}
	return resp, err
}

type teeBody struct {
	io.ReadCloser
	t teeRT
}

func (b teeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		rel := b.t.delivered()
		w := b.t.w
		w.mu.Lock()
		w.headers = true
		w.body.Write(p[:n])
		if !w.sawResult && strings.Contains(w.body.String(), "PART-") {
			w.sawResult, w.releasedFirst = true, rel
		}
		w.mu.Unlock()
	}
	return n, err
}
