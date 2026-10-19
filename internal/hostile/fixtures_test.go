package hostile

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestCatalogMatchesSRS keeps Rows in step with Appendix L.
func TestCatalogMatchesSRS(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "srs_build", "appendix2.md"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "| HF-") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		r, ok := Lookup(cells[0])
		if !ok {
			t.Errorf("%s missing from Rows", cells[0])
			continue
		}
		want := []string{r.ID, r.Attack, r.Behavior, r.Expected, r.Profiles, strings.Join(r.Requirements, ", ")}
		if !slices.Equal(cells, want) {
			t.Errorf("%s differs from the SRS:\n got  %q\n want %q", r.ID, want, cells)
		}
		got = append(got, cells[0])
	}
	if len(got) != len(Rows) || len(Rows) != 27 {
		t.Fatalf("SRS rows %v, catalog %d", got, len(Rows))
	}
	for _, r := range Rows {
		if fixtures[r.ID] == nil {
			t.Errorf("no fixture for %s", r.ID)
		}
	}
	if _, ok := Lookup("hf-01"); !ok {
		t.Fatal("lookup is case-sensitive")
	}
}

// connect runs a fixture in-process and connects an SDK client to it.
func connect(t *testing.T, c Config, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	cr, sw := io.Pipe() // server writes, client reads
	sr, cw := io.Pipe() // client writes, server reads
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, c, sr, sw)
		sw.Close()
	}()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, opts).Connect(ctx,
		&mcp.IOTransport{Reader: cr, Writer: cw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cs.Close()
		cw.Close()
		cancel()
		<-done
	})
	return cs
}

func listNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, *mcp.CallToolResult) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res
}

// TestEveryFixtureServes checks that each fixture completes the MCP
// handshake and lists the tools the suite's policies name.
func TestEveryFixtureServes(t *testing.T) {
	for _, id := range append([]string{"BENIGN", "EGRESS", "PACKAGING"}, func() []string {
		var ids []string
		for _, r := range Rows {
			ids = append(ids, r.ID)
		}
		return ids
	}()...) {
		t.Run(id, func(t *testing.T) {
			c := Config{Fixture: id, CanaryURL: "http://127.0.0.1:9/schema.json"}
			cs := connect(t, c, nil)
			names := listNames(t, cs)
			if !slices.Contains(names, "echo") {
				t.Fatalf("tools %v", names)
			}
			for _, n := range names {
				if !slices.Contains(ToolNames(id, c), n) {
					t.Errorf("ToolNames lacks %s", n)
				}
			}
			if txt, _ := callText(t, cs, "echo", map[string]any{"text": "x"}); !strings.HasPrefix(txt, "echo:x pid=") {
				t.Fatalf("echo %q", txt)
			}
		})
	}
	if ToolNames("HF-99", Config{}) != nil || Tools("HF-99", Config{}) != nil {
		t.Fatal("unknown fixture has tools")
	}
}

func TestContentFixtures(t *testing.T) {
	cs := connect(t, Config{Fixture: "HF-04"}, nil)
	if txt, _ := callText(t, cs, "fetch_page", nil); !strings.Contains(txt, Canary("04")) {
		t.Fatalf("HF-04 %q", txt)
	}
	cs = connect(t, Config{Fixture: "HF-05"}, nil)
	if _, res := callText(t, cs, "fetch_record", nil); !strings.Contains(strings.Join(func() []string {
		m, _ := res.StructuredContent.(map[string]any)
		s, _ := m["summary"].(string)
		return []string{s}
	}(), ""), Canary("05")) {
		t.Fatalf("HF-05 %+v", res.StructuredContent)
	}
	cs = connect(t, Config{Fixture: "HF-06"}, nil)
	if txt, res := callText(t, cs, "fail", nil); !res.IsError || !strings.Contains(txt, Canary("06")) {
		t.Fatalf("HF-06 %q", txt)
	}
	cs = connect(t, Config{Fixture: "HF-27"}, nil)
	if txt, _ := callText(t, cs, "statement", nil); !strings.ContainsRune(txt, '\u202E') || !strings.ContainsRune(txt, '\u200B') {
		t.Fatalf("HF-27 %q", txt)
	}
	cs = connect(t, Config{Fixture: "HF-16", OversizeMiB: 1}, nil)
	if txt, _ := callText(t, cs, "big", nil); len(txt) < 1<<20 {
		t.Fatalf("HF-16 %d bytes", len(txt))
	}
	if !strings.HasPrefix(Canary("hf-07"), CanaryMarker+"INJECTION-07:") {
		t.Fatal(Canary("hf-07"))
	}
}

func TestProgressAndServerRequests(t *testing.T) {
	progress := make(chan string, 4)
	cs := connect(t, Config{Fixture: "HF-07"}, &mcp.ClientOptions{ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
		progress <- r.Params.Message
	}})
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "long_task", Meta: mcp.Meta{"progressToken": "p1"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-progress:
		if !strings.Contains(m, Canary("07")) {
			t.Fatalf("progress %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no progress notification")
	}
	// HF-26: the SDK client answers roots/list itself and has no sampling
	// handler here, so sampling is refused.
	cs = connect(t, Config{Fixture: "HF-26"}, nil)
	if txt, _ := callText(t, cs, "legacy", nil); !strings.Contains(txt, "roots/list=") || !strings.Contains(txt, "sampling/createMessage=error") {
		t.Fatalf("HF-26 %q", txt)
	}
}

func TestRugPullChangesList(t *testing.T) {
	changed := make(chan struct{}, 1)
	cs := connect(t, Config{Fixture: "HF-03"}, &mcp.ClientOptions{ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
		changed <- struct{}{}
	}})
	if names := listNames(t, cs); !slices.Equal(names, []string{"echo"}) {
		t.Fatalf("before %v", names)
	}
	callText(t, cs, "echo", nil)
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("no list_changed")
	}
	if names := listNames(t, cs); !slices.Contains(names, "exfiltrate") {
		t.Fatalf("after %v", names)
	}
	if got := ToolNames("HF-03", Config{}); !slices.Equal(got, []string{"echo", "exfiltrate"}) {
		t.Fatalf("ToolNames %v", got)
	}
	if len(Tools("HF-13", Config{})) != 2 || StrictLookupSchema()["additionalProperties"] != false || LooseLookupSchema()["patternProperties"] == nil {
		t.Fatal("HF-13 schemas")
	}
}

func TestResourceFixturesStopAtTheirCaps(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cs := connect(t, Config{Fixture: "HF-21", AllocMiB: 20}, nil)
	if txt, _ := callText(t, cs, "alloc", nil); txt != "allocated 20 MiB" {
		t.Fatalf("HF-21 %q", txt)
	}
	held = nil
	cs = connect(t, Config{Fixture: "HF-20", Children: 3, Self: []string{exe, SelfFlag}}, nil)
	if txt, _ := callText(t, cs, "spawn", nil); txt != "spawned 3 of 3" {
		t.Fatalf("HF-20 %q", txt)
	}
	children.mu.Lock()
	n := len(children.procs)
	children.mu.Unlock()
	if n != 3 {
		t.Fatalf("%d children tracked", n)
	}
	releaseChildren() // the children see end of file on standard input and exit
	children.mu.Lock()
	n = len(children.procs)
	children.mu.Unlock()
	if n != 0 {
		t.Fatal("children not released")
	}
}

func TestHoldEndsAtEOFOrTimeout(t *testing.T) {
	start := time.Now()
	Hold(strings.NewReader("x"), time.Minute)
	pr, pw := io.Pipe()
	defer pw.Close()
	Hold(pr, 50*time.Millisecond)
	if time.Since(start) > 10*time.Second {
		t.Fatal("hold did not end")
	}
}

func TestDripNeverFinishesALine(t *testing.T) {
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, Config{Fixture: "HF-17", DripEvery: 5 * time.Millisecond}, sr, sw)
		sw.Close()
	}()
	go func() {
		_, _ = io.WriteString(cw, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow","arguments":{}}}`+"\n")
	}()
	br := bufio.NewReader(cr)
	buf := make([]byte, 0, 256)
	for len(buf) < 120 {
		b, err := br.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		if b == '\n' {
			t.Fatal("drip finished a line")
		}
		buf = append(buf, b)
	}
	if !strings.HasPrefix(string(buf), `{"jsonrpc":"2.0","id":7,"result"`) {
		t.Fatalf("%q", buf)
	}
	cancel()
	cw.Close()
	go func() { _, _ = io.Copy(io.Discard, cr) }()
	if err := <-done; err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestMainFlags(t *testing.T) {
	if Main(nil, []string{"-nope"}) != 2 {
		t.Fatal("bad flag accepted")
	}
	if err := Serve(context.Background(), Config{Fixture: "HF-00"}, strings.NewReader(""), io.Discard); !errors.Is(err, ErrUnknownFixture) {
		t.Fatal(err)
	}
}
