package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type fakeReq struct {
	id      string
	verdict RequestVerdict
	err     error
	calls   *[]string
}

func (f fakeReq) ID() string { return f.id }
func (f fakeReq) FilterRequest(_ context.Context, _ *Call, args json.RawMessage) (RequestVerdict, error) {
	*f.calls = append(*f.calls, f.id)
	return f.verdict, f.err
}

type fakeResp struct {
	id      string
	verdict ResponseVerdict
}

func (f fakeResp) ID() string { return f.id }
func (f fakeResp) FilterResponse(context.Context, *Call, *mcp.CallToolResult) (ResponseVerdict, error) {
	return f.verdict, nil
}

func schemaCall() *Call {
	return &Call{InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}, "required": []any{"text"}}}
}

func TestFilterChainOrderSelectionAndFailClosed(t *testing.T) {
	// Chain mechanics with schema-validate; the other FR-4.5 filters are
	// verified in internal/filters.
	reqtest.Partial(t, "FR-4.5")
	var calls []string
	f := NewFilters()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(f.RegisterRequest(fakeReq{id: "late", calls: &calls}, Registration{Order: 300, Mandatory: true}))
	must(f.RegisterRequest(fakeReq{id: "early", calls: &calls}, Registration{Order: 10, Mandatory: true}))
	must(f.RegisterRequest(fakeReq{id: "optional", calls: &calls}, Registration{Order: 200}))
	if err := f.RegisterRequest(fakeReq{id: "early", calls: &calls}, Registration{}); err == nil {
		t.Fatal("duplicate ID accepted")
	}
	call := schemaCall()
	args, applied, v := f.RunRequest(context.Background(), call, json.RawMessage(`{"text":"x"}`))
	if v != nil || strings.Join(applied, ",") != "early,schema-validate,late" || string(args) != `{"text":"x"}` {
		t.Fatalf("%v %v %s", v, applied, args)
	}
	// Obligations select optional filters.
	call.Obligations = policy.Obligations{Filters: []string{"optional"}}
	_, applied, _ = f.RunRequest(context.Background(), call, json.RawMessage(`{"text":"x"}`))
	if strings.Join(applied, ",") != "early,schema-validate,optional,late" {
		t.Fatalf("%v", applied)
	}
	// An obligation naming an unknown filter blocks.
	call.Obligations.Filters = []string{"injection-detect"}
	_, _, v = f.RunRequest(context.Background(), call, json.RawMessage(`{"text":"x"}`))
	if v == nil || v.ReasonCode != ReasonFilterUnavailable {
		t.Fatalf("%+v", v)
	}
	// Schema-validate blocks bad arguments.
	call.Obligations.Filters = nil
	_, _, v = f.RunRequest(context.Background(), call, json.RawMessage(`{"text":7}`))
	if v == nil || v.ReasonCode != ReasonSchemaInvalid {
		t.Fatalf("%+v", v)
	}
	// A failing filter blocks (fail closed); a transform replaces arguments.
	g := NewFilters()
	must(g.RegisterRequest(fakeReq{id: "tx", calls: &calls, verdict: RequestVerdict{Action: Transform, Arguments: json.RawMessage(`{"text":"redacted"}`)}}, Registration{Order: 1, Mandatory: true}))
	args, _, v = g.RunRequest(context.Background(), schemaCall(), json.RawMessage(`{"text":"secret"}`))
	if v != nil || string(args) != `{"text":"redacted"}` {
		t.Fatalf("%v %s", v, args)
	}
	must(g.RegisterRequest(fakeReq{id: "broken", calls: &calls, err: errors.New("boom")}, Registration{Order: 500, Mandatory: true}))
	_, _, v = g.RunRequest(context.Background(), schemaCall(), json.RawMessage(`{"text":"x"}`))
	if v == nil || v.ReasonCode != ReasonFilterError {
		t.Fatalf("%+v", v)
	}
	// Response chain: withhold and transform.
	must(g.RegisterResponse(fakeResp{id: "resp-tx", verdict: ResponseVerdict{Action: Transform, Result: &mcp.CallToolResult{}}}, Registration{Mandatory: true}))
	res, applied, rv := g.RunResponse(context.Background(), schemaCall(), &mcp.CallToolResult{IsError: true})
	if rv != nil || res.IsError || strings.Join(applied, ",") != "resp-tx" {
		t.Fatalf("%v %v %+v", rv, applied, res)
	}
	must(g.RegisterResponse(fakeResp{id: "resp-block", verdict: ResponseVerdict{Action: Block, ReasonCode: "SECRET_IN_RESULT"}}, Registration{Order: 1, Mandatory: true}))
	if _, _, rv = g.RunResponse(context.Background(), schemaCall(), &mcp.CallToolResult{}); rv == nil || rv.ReasonCode != "SECRET_IN_RESULT" {
		t.Fatalf("%+v", rv)
	}
}

func TestCapabilities(t *testing.T) {
	// The dispatcher side of FR-4.13 is verified in the backend tests.
	reqtest.Partial(t, "FR-4.13")
	c := NewCapabilities(time.Minute)
	now := time.Now()
	c.SetNow(func() time.Time { return now })
	b := Binding{CorrelationID: "c1", DecisionID: "d1", PolicyRevision: "r1", PublicName: "t_echo"}
	id := c.Issue(b)
	if err := c.Consume("", b); !errors.Is(err, ErrNoCapability) {
		t.Fatalf("no capability: %v", err)
	}
	other := b
	other.CorrelationID = "c2"
	if err := c.Consume(id, other); !errors.Is(err, ErrCapabilityMismatch) {
		t.Fatalf("another call's capability: %v", err)
	}
	if err := c.Consume(id, b); err != nil {
		t.Fatal(err)
	}
	if err := c.Consume(id, b); !errors.Is(err, ErrCapabilityUsed) {
		t.Fatalf("reuse: %v", err)
	}
	if err := c.Consume("forged", b); !errors.Is(err, ErrCapabilityUnknown) {
		t.Fatalf("forged: %v", err)
	}
	id2 := c.Issue(b)
	now = now.Add(2 * time.Minute)
	if err := c.Consume(id2, b); !errors.Is(err, ErrCapabilityUnknown) {
		t.Fatalf("expired: %v", err)
	}
	c.Prune()
	if c.Outstanding() != 0 {
		t.Fatalf("%d entries after prune", c.Outstanding())
	}
}

func TestCheckLaunchSpec(t *testing.T) {
	// SR-3.6-1 also requires content-addressed artifacts (E-13 packages).
	reqtest.Partial(t, "SR-3.6-1")
	refused := []ServerSpec{
		{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}},
		{Command: "/usr/local/bin/npx"},
		{Command: "/opt/homebrew/bin/uvx", Args: []string{"mcp-server-fetch"}},
		{Command: "/usr/bin/python3", Args: []string{"-m", "pip", "install", "x"}},
		{Command: "/usr/bin/podman", Args: []string{"run", "ghcr.io/x/y:latest"}},
		{Command: "refserver"},
	}
	for _, s := range refused {
		if err := CheckLaunchSpec(s); !errors.Is(err, ErrUnpinnedLaunch) {
			t.Errorf("%v accepted: %v", s, err)
		}
	}
	allowed := []ServerSpec{
		{Command: "/usr/local/bin/smcp-refserver"},
		{Command: "/usr/bin/podman", Args: []string{"run", "ghcr.io/x/y@sha256:abc"}},
		{Command: "/usr/bin/python3", Args: []string{"/opt/srv/server.py"}},
	}
	for _, s := range allowed {
		if err := CheckLaunchSpec(s); err != nil {
			t.Errorf("%v refused: %v", s, err)
		}
	}
}

func TestSubprocessLauncher(t *testing.T) {
	l := SubprocessLauncher{TerminateAfter: 200 * time.Millisecond}
	if l.Confined() || l.Name() != "subprocess" {
		t.Fatal("subprocess launcher claims confinement")
	}
	cat, err := os.Stat("/bin/cat")
	if err != nil || cat.IsDir() {
		t.Skip("no /bin/cat")
	}
	p, err := l.Launch(context.Background(), ServerSpec{Command: "/bin/cat", Env: map[string]string{"SECRET_LEAK": "no"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(p).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("%q %v", line, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal("second close")
	}
	// A process that ignores stdin closure is terminated.
	p, err = l.Launch(context.Background(), ServerSpec{Command: "/bin/sleep", Args: []string{"30"}})
	if err != nil {
		t.Skip("no /bin/sleep")
	}
	start := time.Now()
	p.Close()
	if time.Since(start) > 5*time.Second {
		t.Fatal("termination did not escalate")
	}
	if _, err := l.Launch(context.Background(), ServerSpec{Command: "npx"}); !errors.Is(err, ErrUnpinnedLaunch) {
		t.Fatalf("npx launched: %v", err)
	}
}

func TestManifestSecretsApprover(t *testing.T) {
	live := func(context.Context) ([]*mcp.Tool, error) {
		return []*mcp.Tool{{Name: "b"}, {Name: "a"}}, nil
	}
	ts, err := LiveManifest{}.Tools(context.Background(), ServerSpec{}, live)
	if err != nil || ts.Verified || ts.Source != "live" || ts.Tools[0].Name != "a" || !strings.HasPrefix(ts.Revision, "live-") {
		t.Fatalf("%+v %v", ts, err)
	}
	if _, err := (NoSecrets{}).Resolve(context.Background(), SecretRequest{Refs: map[string]string{"T": "vault:x"}}); !errors.Is(err, ErrNoSecretBroker) {
		t.Fatal(err)
	}
	if env, err := MergeEnv(map[string]string{"PATH": "/bin"}, map[string]string{"A": "1"}, map[string]string{"T": "s"}); err != nil || env["T"] != "s" || env["PATH"] != "/bin" {
		t.Fatalf("%v %v", env, err)
	}
	if _, err := MergeEnv(nil, map[string]string{"T": "1"}, map[string]string{"T": "s"}); err == nil {
		t.Fatal("secret overrode configuration")
	}
	res, err := RefuseApprover{}.Request(context.Background(), ApprovalRequest{})
	if err != nil || res.Outcome != Pending || res.ReasonCode != ReasonApprovalRequired || res.RetryText == "" {
		t.Fatalf("%+v", res)
	}
}
