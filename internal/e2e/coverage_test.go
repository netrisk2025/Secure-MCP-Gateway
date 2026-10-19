package e2e

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestRefreshTokenReuseEndsSession is SR-2.11-4 through the running
// Gateway: after one refresh, presenting the first refresh token again
// terminates the session, the current access token receives -31006 on the
// MCP endpoint, and the journal records the session's end with reason
// REFRESH_TOKEN_REUSE.
func TestRefreshTokenReuseEndsSession(t *testing.T) {
	reqtest.Verifies(t, "SR-2.11-4")
	f := start(t, "")
	_, refresh, tb := f.oauthLogin("")
	sessionID := tb["session_id"].(string)
	refreshWith := func(tok string) (int, map[string]any) {
		r, b := f.postForm(f.base+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {clientID}})
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return r.StatusCode, out
	}
	st, rotated := refreshWith(refresh)
	if st != 200 {
		t.Fatalf("refresh: %d %v", st, rotated)
	}
	current := rotated["access_token"].(string)
	list := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{%s}}`, modernMeta)
	if status, _, body := f.post(list, modernHeaders(current, "tools/list")); status != 200 {
		t.Fatalf("current token before reuse: %d %s", status, body)
	}
	// Replay the rotated-out refresh token.
	if st, body := refreshWith(refresh); st != 400 {
		t.Fatalf("reused refresh token accepted: %d %v", st, body)
	}
	if s := f.app.Store.Get(sessionID); s == nil || s.State == "active" {
		t.Fatalf("session still active after reuse: %+v", s)
	}
	status, _, body := f.post(list, modernHeaders(current, "tools/list"))
	if status != 401 || !strings.Contains(body, fmt.Sprint(edge.CodeSessionInvalid)) {
		t.Fatalf("current access token after reuse: %d %s", status, body)
	}
	// The newest refresh token is dead too.
	if st, _ := refreshWith(rotated["refresh_token"].(string)); st != 400 {
		t.Fatalf("current refresh token survived reuse: %d", st)
	}
	f.stop()
	evs, err := audit.ReadEvents(filepath.Join(f.stateDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Class == "session" && e.SessionID == sessionID && e.ReasonCode == "REFRESH_TOKEN_REUSE" {
			found = true
		}
	}
	if !found {
		t.Fatal("journal has no REFRESH_TOKEN_REUSE session event")
	}
}
