package acceptance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDiagnosticLogExcludesSecrets is FR-17.3's verification against the
// real smcpd at debug level: a secret is stored in the vault, bound to the
// reference server as an S3 file and delivered at launch (which registers
// its leak fingerprints); calls then carry the secret value, a marker
// argument and a refreshed token. The diagnostic log (<state>/log/smcpd.log
// and the daemon's standard output and error) holds none of the secret
// value or a 12-byte piece of it, the access and refresh tokens (before
// and after the refresh), the administrator, approver and vault
// passwords, the argument marker or the tool result. The other levels are
// covered for tokens, passwords, arguments and results by
// TestDiagnosticLogLevelsAndContent.
func TestDiagnosticLogExcludesSecrets(t *testing.T) {
	reqtest.Verifies(t, "FR-17.3")
	if requestedProfile() == reqtest.Enforced {
		// S3 delivery into a rootless Podman instance is covered by the
		// sandbox tests; the diagnostic log does not depend on the profile.
		t.Skip("standalone profile only")
	}
	g := newGateway(t, options{})
	priv := t.TempDir()
	vaultPass := "vault passphrase " + randomString(12)
	pp := writeFile(t, priv, "vault-pass", vaultPass+"\n", 0o600)
	// The binding is added once the secret exists (a launch-time binding
	// to a missing secret refuses the server).
	writeFile(t, g.dir, "secret-use.json", `{"revision": "u0"}`, 0o600)
	bind := func() {
		writeFile(t, g.dir, "secret-use.json", `{"revision": "u1",
  "slots": [{"server": "ref", "name": "token", "modes": ["S3"], "file_env": "REF_TOKEN_FILE"}],
  "policies": [{"id": "ref-token", "secret": "api-key", "server": "ref", "slot": "token", "mode": "S3", "tools": ["*"], "purpose": "diagnostic log test"}]}`, 0o600)
	}
	g.appendConfig(fmt.Sprintf("\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = %q\nuse_policy_file = \"secret-use.json\"\n\n[log]\nlevel = \"debug\"\n", pp))
	g.mustCtl("secrets", "init")
	secret := "diag-secret-" + randomString(24)
	g.start()
	g.mustCtl("secrets", "set", "api-key", "--type", "api_key", "--value-file", writeFile(t, priv, "value", secret+"\n", 0o600))
	g.stop()
	bind()
	// On this start the reference server is launched with the secret.
	logFile := filepath.Join(g.state, "log", "smcpd.log")
	_ = os.Remove(logFile)
	g.start()
	tok := g.freshToken()
	cs := g.session(tok)
	marker := "diag-marker-" + randomString(10)
	result := g.mustCall(cs, "ref_echo", map[string]any{"text": marker}, marker)
	// A call carrying the registered secret is refused before dispatch.
	if text, isErr, err := call(cs, "ref_echo", map[string]any{"text": "token " + secret}); err == nil && !isErr {
		t.Fatalf("a call carrying the secret was answered: %q", text)
	}
	// Refresh the session's tokens and call with the new access token.
	g.mu.Lock()
	rt := g.refresh[tok]
	g.mu.Unlock()
	if rt[0] == "" {
		t.Fatal("no refresh token recorded")
	}
	resp, err := g.httpClient().PostForm(rt[1], url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt[0]}, "client_id": {clientID},
		"resource": {g.publicURL + "/mcp"}})
	if err != nil {
		t.Fatal(err)
	}
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || json.Unmarshal(raw, &refreshed) != nil || refreshed.AccessToken == "" {
		t.Fatalf("refresh: %d %s", resp.StatusCode, raw)
	}
	cs2 := g.session(refreshed.AccessToken)
	g.mustCall(cs2, "ref_echo", map[string]any{"text": marker + "-2"}, marker+"-2")
	cs.Close()
	cs2.Close()
	g.stop()

	file, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file), `"level":"DEBUG"`) {
		t.Fatal("the diagnostic log has no debug lines")
	}
	// The secret was delivered (and its fingerprints registered) at launch,
	// and the call carrying it was refused for it.
	j := g.journalText()
	if !strings.Contains(j, `"class":"secret_use"`) || !strings.Contains(j, `"outcome":"delivered"`) || !strings.Contains(j, "SECRET_IN_ARGUMENTS") {
		t.Fatal("the journal records no secret delivery or no refusal of the call carrying the secret")
	}
	log := string(file) + g.logs.String()
	checks := map[string]string{"secret value": secret, "secret prefix": secret[:12], "secret middle": secret[12:24],
		"access token": tok, "refresh token": rt[0], "refreshed access token": refreshed.AccessToken, "refreshed refresh token": refreshed.RefreshToken,
		"administrator password": adminPassword, "approver password": approverPassword, "vault passphrase": vaultPass,
		"argument marker": marker, "tool result": result}
	for what, v := range checks {
		if v == "" {
			t.Fatalf("%s is empty", what)
		}
		if strings.Contains(log, v) {
			t.Errorf("the diagnostic log holds the %s", what)
		}
	}
}
