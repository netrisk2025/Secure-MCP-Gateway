package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestGraphMirrorDownDoesNotAffectCalls(t *testing.T) {
	// FR-9.17 third case and FR-9 (no enforcement decision depends on the
	// Data Server): with the graph database hung, and then failing, tool
	// calls are served normally; once it recovers the mirror catches up
	// from the journal and holds the calls. Health "degraded" for the
	// graph is not reported by /admin/v1/health yet (E-23).
	reqtest.Partial(t, "FR-9.17", "FR-9")
	f := start(t, "")
	fake := graph.NewFake()
	fake.Block()
	mirror, err := graph.New(graph.Options{Config: f.cfg, Log: diag.Discard(), Backend: fake})
	if err != nil {
		t.Fatal(err)
	}
	f.app.Evidence.AddObserver("graph", mirror, 0)
	mirror.Start(context.Background(), f.app.Evidence)
	t.Cleanup(func() { fake.Unblock(); mirror.Close() })

	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	call := func(n int) {
		t0 := time.Now()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "hi"}})
		if err != nil || res.IsError {
			t.Fatalf("call %d with the graph down: %v %+v", n, err, res)
		}
		if d := time.Since(t0); d > 2*time.Second {
			t.Fatalf("call %d took %v with the graph down", n, d)
		}
	}
	for i := 0; i < 5; i++ {
		call(i)
	}
	fake.Unblock()
	fake.Fail(graph.ErrUnavailable)
	for i := 5; i < 10; i++ {
		call(i)
	}
	fake.Fail(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if _, err := mirror.DAS(); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("mirror never recovered: %+v", mirror.Status(ctx, false))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := mirror.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if n := fake.Count("Invocation"); n != 10 {
		t.Fatalf("mirror holds %d of 10 calls after recovery", n)
	}
}
