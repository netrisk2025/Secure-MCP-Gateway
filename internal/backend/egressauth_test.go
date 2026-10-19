package backend

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// issuingLauncher launches the in-memory server behind a process that
// mints egress capabilities and records the bindings and revocations.
type issuingLauncher struct {
	memLauncher
	mu      sync.Mutex
	issued  []pipeline.Binding
	revoked int
}

type issuingProc struct {
	pipeline.Process
	l *issuingLauncher
}

func (p issuingProc) IssueEgress(b pipeline.Binding) (*pipeline.EgressAuth, func()) {
	p.l.mu.Lock()
	p.l.issued = append(p.l.issued, b)
	p.l.mu.Unlock()
	auth := &pipeline.EgressAuth{
		Header: pipeline.EgressAuthHeader,
		Destinations: []pipeline.EgressCapability{
			{Host: "api.test", Ports: []int{443}, Tokens: []string{"tok-" + b.CorrelationID}},
		},
	}
	revoke := func() {
		p.l.mu.Lock()
		p.l.revoked++
		p.l.mu.Unlock()
	}
	return auth, revoke
}

func (l *issuingLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	p, err := l.memLauncher.Launch(ctx, spec)
	if err != nil {
		return nil, err
	}
	return wrappedProc{issuingProc{Process: p, l: l}}, nil
}

// wrappedProc is a further launcher wrapper (like the Secret Broker's).
type wrappedProc struct{ pipeline.Process }

func (w wrappedProc) Unwrap() pipeline.Process { return w.Process }

// TestDispatchDeliversEgressCapabilities: the Tool Dispatcher asks the
// instance's process (through launcher wrappers) for the egress
// capabilities of the call, bound to the call's correlation ID, decision ID
// and policy revision, delivers them in the tools/call _meta under
// local.smcpgw/egress_auth, and revokes them when the call returns.
func TestDispatchDeliversEgressCapabilities(t *testing.T) {
	reqtest.Partial(t, "SR-5.16-1")
	srv := func() *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "mem", Version: "1"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: "meta"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			raw, _ := json.Marshal(req.Params.Meta[pipeline.EgressAuthMeta])
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}, nil, nil
		})
		return s
	}
	l := &issuingLauncher{memLauncher: memLauncher{build: srv}}
	caps := pipeline.NewCapabilities(time.Minute)
	r, err := Start(context.Background(), []config.Server{{Alias: "m", Command: "/fake/mem"}},
		Options{Limits: Limits{UpstreamTimeout: 5 * time.Second, ResultBytes: 64 << 10, PerPrincipal: 2, Total: 2, Queue: 2}, Launcher: l, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ref := r.Resolve("m_meta")
	if ref == nil {
		t.Fatal("meta tool not indexed")
	}
	res, err := r.Call(context.Background(), dispatch(caps, ref, "c9", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	var got pipeline.EgressAuth
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &got); err != nil {
		t.Fatalf("%v: %s", err, res.Content[0].(*mcp.TextContent).Text)
	}
	if got.Header != "Smcp-Egress-Auth" || got.Take("api.test", 443) != "tok-c9" {
		t.Fatalf("delivered %+v", got)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.issued) != 1 || l.issued[0].CorrelationID != "c9" || l.issued[0].DecisionID != "d-c9" || l.issued[0].PolicyRevision != "r1" || l.revoked != 1 {
		t.Fatalf("issued %+v revoked %d", l.issued, l.revoked)
	}
}
