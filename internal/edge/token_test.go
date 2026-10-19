package edge

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestTokenPresentation is FR-2.5: on the TLS listener the session token
// is accepted in the Authorization header and refused (401, -31006) when
// it is sent only as a query parameter (access_token) or not at all; on
// the UDS listener messages on an authenticated connection are served
// without any token.
func TestTokenPresentation(t *testing.T) {
	reqtest.Verifies(t, "FR-2.5")
	h, path := udsHarness(t, harnessOpts{}, os.Getuid(), "ro")
	_, tok := h.session("ro")
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta)
	post := func(url string, hdr map[string]string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	hdr := wireHeaders(tok, "tools/list")
	if status, b := post(h.srv.URL+"/mcp", hdr); status != 200 || !strings.Contains(b, `"t_echo"`) {
		t.Fatalf("header: %d %s", status, b)
	}
	delete(hdr, "Authorization")
	for name, url := range map[string]string{
		"query parameter": h.srv.URL + "/mcp?access_token=" + tok,
		"no token":        h.srv.URL + "/mcp",
	} {
		status, b := post(url, hdr)
		wantError(t, name, status, b, 401, CodeSessionInvalid)
	}
	c := dialUDS(t, path)
	c.authenticate(udsKey)
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta))
	if r := c.reply("7"); r["result"] == nil {
		t.Fatalf("uds message without a token: %v", r)
	}
}
