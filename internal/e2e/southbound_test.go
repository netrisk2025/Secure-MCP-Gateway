package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSouthboundCarriesNoNorthboundCredentials is SR-2.10-1: what a server
// receives for a call (the raw tools/call parameters, including _meta, and
// its process environment) holds none of the harness's credential
// material: no access or refresh token, no session ID, no Authorization
// header or bearer value, no OAuth client identifier, and no control-API
// token, even when the harness puts its own Authorization-like values in
// _meta. stdio carries no headers; these are the only southbound channels.
func TestSouthboundCarriesNoNorthboundCredentials(t *testing.T) {
	reqtest.Verifies(t, "SR-2.10-1")
	f := start(t, "")
	f.publish(strings.Replace(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1), `"tools": ["echo", "dotted.name"`, `"tools": ["southbound", "echo", "dotted.name"`, 1))
	access, refresh, body := f.oauthLogin("")
	sessionID, _ := body["session_id"].(string)
	cs := f.mcpClient(access)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_southbound", Arguments: map[string]any{"q": "x"},
		Meta: mcp.Meta{"progressToken": "pt-1", "authorization": "Bearer " + access, "smcp/session": refresh}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got := res.Content[0].(*mcp.TextContent).Text
	var seen struct {
		Params map[string]any `json:"params"`
		Env    []string       `json:"env"`
	}
	if err := json.Unmarshal([]byte(got), &seen); err != nil || seen.Params["name"] != "southbound" || len(seen.Env) == 0 {
		t.Fatalf("capture: %v %s", err, got)
	}
	secrets := map[string]string{"access token": access, "refresh token": refresh, "operator token": f.operator, "client ID": clientID}
	if sessionID != "" {
		secrets["session ID"] = sessionID
	}
	for what, v := range secrets {
		if v != "" && strings.Contains(got, v) {
			t.Errorf("the server received the %s", what)
		}
	}
	// The _meta channel is captured: the Gateway's own progress token is there.
	if m, _ := seen.Params["_meta"].(map[string]any); m == nil || m["progressToken"] == nil {
		t.Fatalf("no _meta in the capture: %v", seen.Params)
	}
	low := strings.ToLower(got)
	for _, marker := range []string{"authorization", "bearer ", "mcp-session-id", "cookie"} {
		if strings.Contains(low, marker) {
			t.Errorf("the server received %q: %s", marker, got)
		}
	}
	if args, _ := seen.Params["arguments"].(map[string]any); args["q"] != "x" {
		t.Fatalf("arguments did not reach the server: %v", seen.Params)
	}
}
