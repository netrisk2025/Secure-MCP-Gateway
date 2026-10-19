package remote_test

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// pageText returns the visible text of an HTML page with one blank line
// between elements, as internal/e2e's FR-2.23 check reads the local page.
func pageText(page []byte) string {
	return html.UnescapeString(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(string(page), "\n"))
}

// TestRemoteSignInPageNamesTemplate: the Remote Access sign-in pages (the
// authorization-code page and the device verification page) name the
// client, principal, requested template and scope like the local page of
// FR-2.19, before the Session Approver approves.
func TestRemoteSignInPageNamesTemplate(t *testing.T) {
	reqtest.Partial(t, "FR-2.23")
	e := newEnv(t, "")
	e.enable()
	_, challenge := pkce()
	scope := "smcp:template:remote smcp:purpose:review"
	q := authorizeQuery(gwtest.PreClientID, "http://127.0.0.1/callback", challenge, scope, e.public+"/mcp")
	resp, body := e.get(e.public + "/oauth/authorize?" + q.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize page: %d %s", resp.StatusCode, body)
	}
	text := pageText(body)
	for _, want := range []string{"Client\n\n" + gwtest.PreClientID, "Principal\n\n", "Requested template\n\nremote", "Requested scope\n\n" + scope} {
		if !strings.Contains(text, want) {
			t.Errorf("authorize page lacks %q:\n%s", want, text)
		}
	}
	// Without a template in the scope the page says which default applies.
	q.Set("scope", "")
	if _, body := e.get(e.public + "/oauth/authorize?" + q.Encode()); !strings.Contains(pageText(body), "Requested template\n\n(default template") {
		t.Errorf("authorize page without a template:\n%s", pageText(body))
	}

	// Device verification page.
	r, da := e.postForm(e.public+"/oauth/device_authorization", url.Values{"scope": {"smcp:template:remote"}}, gwtest.PreClientID, gwtest.PreSecret)
	if r.StatusCode != 200 {
		t.Fatalf("device authorization: %d %v", r.StatusCode, da)
	}
	_, page := e.get(e.public + "/oauth/device?user_code=" + url.QueryEscape(da["user_code"].(string)))
	if text := pageText(page); !strings.Contains(text, "Requested template\n\nremote") || !strings.Contains(text, "Client\n\n"+gwtest.PreClientID) {
		t.Errorf("device page lacks the client or template:\n%s", text)
	}
	if _, page := e.get(e.public + "/oauth/device"); !strings.Contains(pageText(page), "Requested template\n\n-") {
		t.Errorf("device page without a code:\n%s", pageText(page))
	}
}
