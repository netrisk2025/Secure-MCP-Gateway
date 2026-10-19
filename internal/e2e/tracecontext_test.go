package e2e

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestTraceContextObserved is FR-1.44 and FR-1.45 end to end: a tools/call
// whose _meta carries a W3C traceparent, tracestate, baggage and a forged
// io.modelcontextprotocol/clientInfo
//   - produces an observation record with trace_parent (P-009) set to the
//     traceparent and harness_adapter_version (P-003) set to the clientInfo
//     name and version,
//   - reaches the backend with none of those keys in its _meta,
//   - leaves no trace of the clientInfo or the trace keys in the decision
//     record or any other evidence event (the decision inputs).
func TestTraceContextObserved(t *testing.T) {
	reqtest.Verifies(t, "FR-1.44", "FR-1.45")
	of := startObservation(t, "sampling_rate = 1.0\nflush_interval = \"20ms\"")
	access, _, _ := of.oauthLogin("smcp:template:ro")
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	meta := fmt.Sprintf(`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},`+
		`"traceparent":%q,"tracestate":"vendor=opaque","baggage":"user=alice","io.modelcontextprotocol/clientInfo":{"name":"forged-agent","version":"6.6.6"}}`, tp)
	hdr := modernHeaders(access, "tools/call")
	hdr["Mcp-Name"] = "t_echo"
	status, _, body := of.post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"show-meta"},`+meta+`}}`, hdr)
	if status != 200 {
		t.Fatalf("%d %s", status, body)
	}
	var reply struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Meta map[string]any `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &reply); err != nil || len(reply.Result.Content) != 1 {
		t.Fatalf("%v %s", err, body)
	}
	seen := reply.Result.Content[0].Text
	if !strings.HasPrefix(seen, "meta:") {
		t.Fatalf("backend reply %q", seen)
	}
	for _, k := range []string{"traceparent", "tracestate", "baggage", "clientInfo"} {
		if strings.Contains(seen, k) {
			t.Fatalf("backend received %s in _meta: %q", k, seen)
		}
	}
	prov, _ := reply.Result.Meta["local.smcpgw/provenance"].(map[string]any)
	decision, _ := prov["decisionId"].(string)

	of.waitAssembled(1)
	of.obs.Sync()
	var rec obsstore.Row
	if err := of.obs.Store.Scan("records", obsstore.Filter{}, func(r obsstore.Row) error {
		if r["tool_name"] == "echo" {
			rec = r
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("no observation record")
	}
	if rec["trace_parent"] != tp || rec["harness_adapter_version"] != "forged-agent/6.6.6" {
		t.Fatalf("observation record: trace_parent %v, harness_adapter_version %v", rec["trace_parent"], rec["harness_adapter_version"])
	}

	evs, err := audit.ReadEvents(filepath.Join(of.stateDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		raw, _ := json.Marshal(e)
		for _, s := range []string{"forged-agent", "4bf92f3577b34da6a3ce929d0e0e4736", "vendor=opaque", "user=alice"} {
			if strings.Contains(string(raw), s) {
				t.Fatalf("evidence event %s/%s carries %q", e.Class, e.Phase, s)
			}
		}
		if e.Class == "decision" && e.DecisionID == decision {
			found = true
		}
	}
	if !found {
		t.Fatalf("no decision record for %s", decision)
	}
}
