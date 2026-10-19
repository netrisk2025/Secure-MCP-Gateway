package session

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type oauthFixture struct {
	t        *testing.T
	srv      *httptest.Server
	oauth    *OAuth
	store    *Store
	rec      *audit.Memory
	client   *http.Client
	resource string
	now      time.Time
}

const (
	clientID = "https://client.example/metadata"
	redirect = "http://localhost:51234/callback"
	verifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
)

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func newOAuthFixture(t *testing.T, guard authguard.Config) *oauthFixture {
	t.Helper()
	approverHash, _ := keys.HashPassword("approver password 1")
	adminHash, _ := keys.HashPassword("admin password 12")
	secretHash, _ := keys.HashPassword("helper-secret-123")
	toml := `
[admin]
username = "admin"
password_hash = "` + adminHash + `"
[[approver]]
username = "ethan"
password_hash = "` + approverHash + `"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = "` + clientID + `"
principal = "cc"
redirect_uris = ["http://localhost:*/callback"]
[[client]]
client_id = "helper"
client_secret_hash = "` + secretHash + `"
principal = "cc"
redirect_uris = ["http://localhost/unused"]
`
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := policy.Compile([]byte(pol))
	f := &oauthFixture{t: t, rec: &audit.Memory{}, now: time.Now()}
	f.store = NewStore(cfg, func() *policy.Snapshot { return snap })
	guard.Now = func() time.Time { return f.now }
	f.oauth = NewOAuth(cfg, f.store, f.rec, authguard.New(guard))
	f.oauth.SetNow(func() time.Time { return f.now })
	mux := http.NewServeMux()
	f.oauth.Register(mux)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	cfg.Listener.PublicURL = f.srv.URL
	f.resource = cfg.ResourceURI()
	f.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}

func (f *oauthFixture) authorizeForm(user, pw string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"s1"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "resource": {f.resource},
		"username": {user}, "password": {pw}}
}

func (f *oauthFixture) postForm(path string, v url.Values) *http.Response {
	f.t.Helper()
	r, err := f.client.PostForm(f.srv.URL+path, v)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// code signs in and returns an authorization code.
func (f *oauthFixture) code() string {
	f.t.Helper()
	r := f.postForm(pathAuthorize, f.authorizeForm("ethan", "approver password 1"))
	r.Body.Close()
	if r.StatusCode != 302 {
		f.t.Fatalf("authorize: %d", r.StatusCode)
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	return loc.Query().Get("code")
}

func (f *oauthFixture) redeem(code, verifier, redirectURI string) (int, map[string]any) {
	f.t.Helper()
	r := f.postForm(pathToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {f.resource}})
	defer r.Body.Close()
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	return r.StatusCode, body
}

func TestAuthorizationCodeNegativeCases(t *testing.T) {
	reqtest.Verifies(t, "FR-2.19", "FR-2.20")
	f := newOAuthFixture(t, authguard.Config{})
	// Wrong PKCE verifier.
	if st, body := f.redeem(f.code(), strings.Repeat("w", 50), redirect); st != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong PKCE: %d %v", st, body)
	}
	// Wrong redirect URI.
	if st, body := f.redeem(f.code(), verifier, "http://localhost:9999/callback"); st != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong redirect: %d %v", st, body)
	}
	// Expired code.
	c := f.code()
	f.now = f.now.Add(codeLifetime + time.Second)
	if st, _ := f.redeem(c, verifier, redirect); st != 400 {
		t.Fatalf("expired code: %d", st)
	}
	// A code is spent even by a failed redemption, and cannot be reused.
	c = f.code()
	if st, _ := f.redeem(c, verifier, redirect); st != 200 {
		t.Fatalf("valid code: %d", st)
	}
	if st, _ := f.redeem(c, verifier, redirect); st != 400 {
		t.Fatalf("reused code: %d", st)
	}
	c = f.code()
	f.redeem(c, strings.Repeat("w", 50), redirect)
	if st, _ := f.redeem(c, verifier, redirect); st != 400 {
		t.Fatalf("code survived a failed redemption: %d", st)
	}
	// The administrator account cannot approve harness sign-ins.
	r := f.postForm(pathAuthorize, f.authorizeForm("admin", "admin password 12"))
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("admin approved a sign-in: %d", r.StatusCode)
	}
	// Unregistered redirect and missing PKCE.
	q := f.authorizeForm("ethan", "approver password 1")
	q.Set("redirect_uri", "http://evil.example/cb")
	if r := f.postForm(pathAuthorize, q); r.StatusCode != 400 {
		t.Fatalf("unregistered redirect: %d", r.StatusCode)
	}
	q = f.authorizeForm("ethan", "approver password 1")
	q.Set("code_challenge_method", "plain")
	r = f.postForm(pathAuthorize, q)
	r.Body.Close()
	if loc, _ := url.Parse(r.Header.Get("Location")); r.StatusCode != 302 || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE: %d %v", r.StatusCode, r.Header.Get("Location"))
	}
	// Expired codes are pruned.
	f.code()
	f.now = f.now.Add(codeLifetime + time.Second)
	f.oauth.Prune()
	if f.oauth.Codes() != 0 {
		t.Fatalf("%d codes after prune", f.oauth.Codes())
	}
}

func TestSignInLockoutAndHeaders(t *testing.T) {
	reqtest.Verifies(t, "FR-2.19")
	f := newOAuthFixture(t, authguard.Config{MaxFailures: 3, LockoutBase: time.Minute, PerSourcePerMinute: 100})
	r, _ := f.client.Get(f.srv.URL + pathAuthorize + "?" + f.authorizeForm("", "").Encode())
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	csp := r.Header.Get("Content-Security-Policy")
	if r.StatusCode != 200 || !strings.Contains(csp, "frame-ancestors 'none'") || r.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(string(body), "Session Approver") {
		t.Fatalf("%d %q %q", r.StatusCode, csp, r.Header.Get("X-Frame-Options"))
	}
	for i := 0; i < 3; i++ {
		r := f.postForm(pathAuthorize, f.authorizeForm("ethan", "wrong"))
		r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, r.StatusCode)
		}
	}
	// Locked: even the right password is refused, with Retry-After.
	r = f.postForm(pathAuthorize, f.authorizeForm("ethan", "approver password 1"))
	r.Body.Close()
	if r.StatusCode != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("locked sign-in: %d", r.StatusCode)
	}
	f.now = f.now.Add(2 * time.Minute)
	f.code() // lock expired
	n := 0
	for _, e := range f.rec.Events() {
		if e.ReasonCode == "APPROVER_SIGNIN_FAILED" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%d failures recorded", n)
	}
	// Metadata no longer advertises unimplemented CIMD support.
	r, _ = f.client.Get(f.srv.URL + pathASM)
	var asm map[string]any
	json.NewDecoder(r.Body).Decode(&asm)
	r.Body.Close()
	if _, ok := asm["client_id_metadata_document_supported"]; ok {
		t.Fatal("CIMD support advertised")
	}
}

func TestTokenEndpointRateLimitAndRefreshReuse(t *testing.T) {
	reqtest.Verifies(t, "FR-2.22")
	f := newOAuthFixture(t, authguard.Config{PerSourcePerMinute: 6})
	st, body := f.redeem(f.code(), verifier, redirect)
	if st != 200 {
		t.Fatal(st)
	}
	refresh := body["refresh_token"].(string)
	refreshOnce := func(tok string) (int, map[string]any) {
		r := f.postForm(pathToken, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {clientID}})
		defer r.Body.Close()
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		return r.StatusCode, b
	}
	st, b2 := refreshOnce(refresh)
	if st != 200 || b2["refresh_token"] == refresh {
		t.Fatalf("rotation: %d %v", st, b2)
	}
	if st, b3 := refreshOnce(refresh); st != 400 || !strings.Contains(b3["error_description"].(string), "reuse") {
		t.Fatalf("reuse: %d %v", st, b3)
	}
	if st, _ := refreshOnce(b2["refresh_token"].(string)); st != 400 {
		t.Fatalf("family survived reuse: %d", st)
	}
	// The token endpoint is rate limited per source.
	limited := false
	for i := 0; i < 10; i++ {
		if st, _ := refreshOnce("x"); st == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("token endpoint not rate limited")
	}
}

func TestSessionCreationFailsClosedWithoutEvidence(t *testing.T) {
	reqtest.Partial(t, "SR-6.1-1")
	f := newOAuthFixture(t, authguard.Config{})
	c := f.code()
	f.rec.Fail(errors.New("disk full"))
	if st, body := f.redeem(c, verifier, redirect); st != 503 {
		t.Fatalf("session issued without evidence: %d %v", st, body)
	}
	if len(f.store.Active()) != 0 {
		t.Fatal("session left active")
	}
	// Session API: unknown client and public client are refused alike.
	f.rec.Fail(nil)
	for _, auth := range [][2]string{{"nobody", "x"}, {clientID, "x"}, {"helper", "wrong"}} {
		req, _ := http.NewRequest("POST", f.srv.URL+pathSessions, strings.NewReader(`{}`))
		req.SetBasicAuth(auth[0], auth[1])
		r, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatalf("%v: %d", auth, r.StatusCode)
		}
	}
}
