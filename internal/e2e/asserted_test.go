package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestServerAssertedEvidence: the backend's stderr, the message of a
// JSON-RPC error it returned and a notification it sent are stored as
// server_asserted events attributed to the server revision and instance,
// labelled with the backend origin, bounded in size, and kept out of the
// harness's view (SR-6.18-1).
func TestServerAssertedEvidence(t *testing.T) {
	reqtest.Verifies(t, "SR-6.18-1")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_noisy", Arguments: map[string]any{}}); err != nil || res.IsError {
		t.Fatalf("noisy: %v %+v", err, res)
	}
	we, data := callErr(t, cs, "t_rpcerror", nil)
	if strings.Contains(we.Message, "internal backend detail") || strings.Contains(fmt.Sprint(data), "internal backend detail") {
		t.Fatalf("backend error text reached the harness: %s", we)
	}
	rev := f.app.Registry.Servers()["t"].Revision

	want := map[string]func(map[string]any) bool{
		"stderr": func(d map[string]any) bool {
			return strings.Contains(d["text"].(string), strings.TrimSpace(stderrMarker))
		},
		"error": func(d map[string]any) bool {
			return d["text"] == "internal backend detail that must not leak" && d["code"] == float64(-32001)
		},
		"notification": func(d map[string]any) bool {
			return d["method"] == "notifications/progress" && strings.Contains(d["text"].(string), "noisy done")
		},
	}
	found := map[string]audit.Event{}
	deadline := time.Now().Add(15 * time.Second)
	for len(found) < len(want) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		evs, err := audit.ReadEvents(filepath.Join(f.stateDir, "journal"))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			if e.Class != "server_asserted" {
				continue
			}
			d, _ := e.Detail.(map[string]any)
			if ok := want[e.Outcome]; ok != nil && ok(d) {
				found[e.Outcome] = e
			}
		}
	}
	for kind := range want {
		e, ok := found[kind]
		if !ok {
			t.Fatalf("no server_asserted %s event", kind)
		}
		d := e.Detail.(map[string]any)
		inst, _ := d["instance"].(string)
		if e.ServerRevision != rev || d["server"] != "t" || !strings.HasPrefix(inst, "t#") {
			t.Fatalf("%s not attributed to the instance: revision %q detail %v", kind, e.ServerRevision, d)
		}
		if audit.OriginLabel(e) != audit.OriginBackend || e.PolicyStatus != "not_evaluated" || e.CorrelationID != "" || e.DecisionID != "" {
			t.Fatalf("%s labelled %q: %+v", kind, audit.OriginLabel(e), e)
		}
		if n := len(d["text"].(string)); n > 4<<10 {
			t.Fatalf("%s text holds %d bytes", kind, n)
		}
	}
	// 10 MiB of stderr is recorded in bounded form: the cut and the
	// overwritten bytes are counted, not stored.
	d := found["stderr"].Detail.(map[string]any)
	if d["truncated_bytes"] == nil && d["skipped_bytes"] == nil {
		t.Fatalf("10 MiB of stderr recorded without a bound: %v", d)
	}
}
