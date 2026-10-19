package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestProjectRootNarrowsGrantedRoots is FR-2.7 as the SRS states it: the
// project-root claim of a session (the smcp:project scope) narrows the
// selected template's granted path roots. With the roots granting /p, a
// session for project /p/a may use paths under /p/a and is refused paths
// elsewhere under /p, a session without the claim may use all of /p, and a
// session whose project root lies outside /p may use no path at all. The
// purpose and end-user claims are recorded with the session and its
// evidence (TestSessionContextKey, FR-2.3).
func TestProjectRootNarrowsGrantedRoots(t *testing.T) {
	reqtest.Verifies(t, "FR-2.7")
	root := filepath.Join(t.TempDir(), "p")
	for _, d := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	f := startWith(t, "", fmt.Sprintf("[filters.paths]\nroots = [%q]\n", root))
	f.publish(strings.Replace(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1), `"tools": ["echo", "dotted.name"`, `"tools": ["southbound", "echo", "dotted.name"`, 1))

	call := func(cs *mcp.ClientSession, path string) (int64, string) {
		t.Helper()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_southbound", Arguments: map[string]any{"path": path}})
		if err == nil && !res.IsError {
			return 0, ""
		}
		we, data := callErr(t, cs, "t_southbound", map[string]any{"path": path})
		reason, _ := data["reasonCode"].(string)
		return we.Code, reason
	}
	inA, inB := filepath.Join(root, "a", "f.txt"), filepath.Join(root, "b", "f.txt")

	access, _, body := f.oauthLogin("smcp:project:" + filepath.Join(root, "a"))
	if !strings.Contains(fmt.Sprint(body["scope"]), "smcp:project:"+filepath.Join(root, "a")) {
		t.Fatalf("project claim not in the granted scope: %v", body["scope"])
	}
	cs := f.mcpClient(access)
	if code, r := call(cs, inA); code != 0 {
		t.Fatalf("path inside the project root: %d %s", code, r)
	}
	if code, r := call(cs, inB); code != -31001 || r != filters.ReasonPathOutsideRoots {
		t.Fatalf("path outside the project root: %d %s", code, r)
	}

	access, _, _ = f.oauthLogin("")
	cs = f.mcpClient(access)
	for _, p := range []string{inA, inB} {
		if code, r := call(cs, p); code != 0 {
			t.Fatalf("no project claim, %s: %d %s", p, code, r)
		}
	}

	access, _, _ = f.oauthLogin("smcp:project:" + outside)
	cs = f.mcpClient(access)
	for _, p := range []string{inA, filepath.Join(outside, "f.txt")} {
		if code, r := call(cs, p); code != -31001 || r != filters.ReasonPathOutsideRoots {
			t.Fatalf("project outside the roots, %s: %d %s", p, code, r)
		}
	}
	// A call without a path argument is not affected.
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err != nil || res.IsError {
		t.Fatalf("echo with an outside project root: %v %+v", err, res)
	}
}
