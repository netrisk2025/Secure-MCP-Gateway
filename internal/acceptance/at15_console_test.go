package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const auditorPassword = "acceptance auditor password 1"

// browser is a console session: the session cookie, its CSRF token and the
// last control-state revision seen.
type browser struct {
	g      *gateway
	cookie string
	csrf   string
	etag   string
}

// browserLogin signs in like the console does (X-SMCP-Session: cookie).
func (g *gateway) browserLogin(path string, body map[string]any) *browser {
	g.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", g.adminURL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SMCP-Session", "cookie")
	resp, err := g.httpClient().Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	br := &browser{g: g, etag: resp.Header.Get("ETag")}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-smcp-session" {
			br.cookie = c.Value
		}
	}
	br.csrf, _ = out["csrf_token"].(string)
	if resp.StatusCode != 200 || br.cookie == "" || br.csrf == "" {
		g.t.Fatalf("browser login %s: %d %s", path, resp.StatusCode, raw)
	}
	return br
}

// do sends a request with the session cookie; csrf and ifMatch are sent
// when not empty.
func (b *browser) do(method, path, csrf, ifMatch string, body any) (int, string) {
	b.g.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, b.g.adminURL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: "__Host-smcp-session", Value: b.cookie})
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := b.g.httpClient().Do(req)
	if err != nil {
		b.g.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if e := resp.Header.Get("ETag"); e != "" {
		b.etag = e
	}
	return resp.StatusCode, string(raw)
}

// TestAT15ConsoleAuthority is acceptance scenario AT-15 against the real
// smcpd's control API, with the requests a browser session makes:
//
//   - a harness access token is refused by the control API (SR-2.5-1);
//   - an Auditor signed in to the console can read the journal but every
//     mutation is refused, even with a valid CSRF token and revision;
//   - an Administrator browser session's mutation without a CSRF token,
//     with a wrong one, and with a stale If-Match revision is refused, and
//     the same mutation with both is accepted (SR-8.9-1);
//   - an approval is single use: approving it again is refused, and an
//     identical second call needs a new approval (SR-1.18-2 in part).
//
// The browser rendering half of AT-15 is in console/e2e (Playwright); this
// test drives the same control API routes without a browser. Partial:
// SR-1.18-2 does not retry with changed arguments, another session or after
// expiry here (internal/approval and internal/e2e do).
func TestAT15ConsoleAuthority(t *testing.T) {
	needBinaries(t)
	priv := t.TempDir()
	pw := writeFile(t, priv, "auditor.pw", auditorPassword+"\n", 0o600)
	// The hash is computed by the real smcpctl.
	hashOut, err := (&gateway{t: t}).ctlRaw("hash-password", "--password-file", pw)
	if err != nil {
		t.Fatalf("hash-password: %v %s", err, hashOut)
	}
	hash := strings.TrimSpace(hashOut[strings.LastIndex(hashOut, "$argon2id"):])
	g := newGateway(t, options{extra: fmt.Sprintf("\n[[console.account]]\nusername = \"auditor\"\npassword_hash = %q\nrole = \"auditor\"\n", hash)})
	if err := os.WriteFile(filepath.Join(g.sandbox, "held.txt"), []byte("held-marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.start()
	g.scenario("AT-15")
	reqtest.Partial(t, "SR-2.5-1", "SR-8.9-1", "SR-1.18-2")

	// SR-2.5-1: harness credentials on the control API.
	harness := g.token("")
	for _, path := range []string{"/api/v1/health/status", "/api/v1/sessions", "/api/v1/audit/events"} {
		if code, _ := g.apiAs(harness, "GET", path, nil); code != http.StatusUnauthorized {
			t.Fatalf("harness token on %s: %d", path, code)
		}
	}
	if code, _ := g.apiAs(harness, "POST", "/admin/v1/stop", map[string]any{"reason": "harness"}); code != http.StatusUnauthorized {
		t.Fatalf("harness token stopped the Gateway: %d", code)
	}

	// Auditor: reads yes, mutations no.
	aud := g.browserLogin("/api/v1/console/login", map[string]any{"username": "auditor", "password": auditorPassword, "role": "auditor"})
	if code, body := aud.do("GET", "/api/v1/audit/events?limit=5", "", "", nil); code != 200 {
		t.Fatalf("auditor reading the journal: %d %s", code, body)
	}
	for _, m := range []struct{ path string }{{"/admin/v1/stop"}, {"/api/v1/policy/rollback"}, {"/api/v1/principals/claude-code-local/suspend"}} {
		if code, body := aud.do("POST", m.path, aud.csrf, aud.etag, map[string]any{"reason": "auditor"}); code != http.StatusForbidden {
			t.Fatalf("auditor mutation %s: %d %s", m.path, code, body)
		}
	}

	// Administrator browser session: CSRF token and If-Match.
	adm := g.browserLogin("/admin/v1/login", map[string]any{"username": "admin", "password": adminPassword})
	if code, _ := adm.do("GET", "/api/v1/health/status", "", "", nil); code != 200 {
		t.Fatalf("admin read: %d", code)
	}
	stale := adm.etag
	// Another actor stops and resumes the Gateway: the browser's revision
	// is stale for the run state (revisions are per object).
	if code, out := g.api("POST", "/admin/v1/stop", map[string]any{"reason": "bump revision"}); code >= 300 {
		t.Fatalf("stop: %d %v", code, out)
	}
	if code, out := g.api("POST", "/admin/v1/resume", map[string]any{}); code >= 300 {
		t.Fatalf("resume: %d %v", code, out)
	}
	stop := map[string]any{"reason": "AT-15"}
	if code, body := adm.do("POST", "/admin/v1/stop", "", stale, stop); code != http.StatusForbidden {
		t.Fatalf("mutation without a CSRF token: %d %s", code, body)
	}
	if code, body := adm.do("POST", "/admin/v1/stop", "wrong-token", stale, stop); code != http.StatusForbidden {
		t.Fatalf("mutation with a wrong CSRF token: %d %s", code, body)
	}
	if code, body := adm.do("POST", "/admin/v1/stop", adm.csrf, stale, stop); code != http.StatusPreconditionFailed {
		t.Fatalf("mutation with a stale revision: %d %s", code, body)
	}
	if code, body := adm.do("POST", "/admin/v1/stop", adm.csrf, adm.etag, stop); code != 200 {
		t.Fatalf("mutation with the CSRF token and the current revision: %d %s", code, body)
	}
	if code, body := adm.do("POST", "/admin/v1/resume", adm.csrf, adm.etag, map[string]any{}); code != 200 {
		t.Fatalf("resume: %d %s", code, body)
	}

	// Approval replay.
	cs := g.session(g.token("smcp:template:approval-demo"))
	held := func() (string, chan error) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			text, isErr, err := call(cs, "ref_read_file", map[string]any{"path": "held.txt"})
			if err == nil && (isErr || !strings.Contains(text, "held-marker")) {
				err = fmt.Errorf("tool error %v: %q", isErr, text)
			}
			done <- err
		}()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			_, list := g.api("GET", "/api/v1/approvals?state=pending", nil)
			if items, _ := list["approvals"].([]any); len(items) > 0 {
				id, _ := items[0].(map[string]any)["id"].(string)
				return id, done
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("no pending approval")
		return "", nil
	}
	id, done := held()
	if code, out := g.api("POST", "/api/v1/approvals/"+id+"/approve", map[string]any{"comment": "AT-15"}); code != 200 {
		t.Fatalf("approve: %d %v", code, out)
	}
	if err := <-done; err != nil {
		t.Fatalf("approved call: %v", err)
	}
	if code, _ := g.api("POST", "/api/v1/approvals/"+id+"/approve", map[string]any{"comment": "replay"}); code != http.StatusConflict {
		t.Fatalf("approving a consumed approval again: %d", code)
	}
	id2, done2 := held()
	if id2 == id {
		t.Fatal("the second identical call reused the first approval")
	}
	if code, _ := g.api("POST", "/api/v1/approvals/"+id2+"/deny", map[string]any{"comment": "AT-15"}); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	if err := <-done2; err == nil {
		t.Fatal("a denied call was released")
	}
	g.stop()
}

// ctlRaw runs smcpctl without adding --config.
func (g *gateway) ctlRaw(args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "smcpctl"), args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}
