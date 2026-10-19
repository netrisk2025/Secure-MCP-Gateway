package remote_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
)

// When every pending registration slot is taken, a further registration is
// refused before the Gateway hashes a client secret or writes evidence, so
// an unauthenticated caller cannot use the endpoint to burn Argon2id
// memory or fill the journal.
func TestRegistrationRefusedWhenFullBeforeWork(t *testing.T) {
	e := newEnv(t, "max_pending_registrations = 2\n")
	e.enable()
	post := func() (*http.Response, []byte) {
		b, _ := json.Marshal(map[string]any{"redirect_uris": []string{"http://127.0.0.1/callback"}, "client_name": "Flood",
			"token_endpoint_auth_method": "client_secret_basic"})
		req, _ := http.NewRequest("POST", e.public+"/oauth/register", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		return e.do(req)
	}
	for i := range 2 {
		if resp, raw := post(); resp.StatusCode != http.StatusCreated {
			t.Fatalf("registration %d: %d %s", i, resp.StatusCode, raw)
		}
	}
	count := func() int {
		n := 0
		for _, ev := range e.Events() {
			if ev.Class == "client_registration" {
				n++
			}
		}
		return n
	}
	e.WaitEvent(func(ev audit.Event) bool { return ev.Class == "client_registration" && count() == 2 })
	for range 3 {
		if resp, raw := post(); resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("registration while full: %d %s", resp.StatusCode, raw)
		}
	}
	if n := count(); n != 2 {
		t.Fatalf("%d client_registration events, want 2: refused registrations must not write evidence", n)
	}
}

// A second redemption of a remote authorization code revokes the session
// the first one created.
func TestRemoteAuthorizationCodeReuseRevokesSession(t *testing.T) {
	e := newEnv(t, "")
	e.enable()
	id := e.register("http://127.0.0.1/callback")["client_id"].(string)
	if st, body := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{}); st != 200 {
		t.Fatalf("approve %d %v", st, body)
	}
	redirect := "http://127.0.0.1/callback"
	verifier, challenge := pkce()
	q := authorizeQuery(id, redirect, challenge, "smcp:template:remote", e.public+"/mcp")
	q.Set("username", gwtest.ApproverUser)
	q.Set("password", gwtest.ApproverPassword)
	resp, _ := e.postForm(e.public+"/oauth/authorize", q, "", "")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if resp.StatusCode != http.StatusFound || code == "" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "client_id": {id}}
	r1, tok := e.postForm(e.public+"/oauth/token", v, "", "")
	if r1.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("first redemption: %d %v", r1.StatusCode, tok)
	}
	list := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
	if r, _ := e.mcp(e.public, tok["access_token"].(string), list); r.StatusCode != 200 {
		t.Fatalf("fresh session refused: %d", r.StatusCode)
	}
	r2, body := e.postForm(e.public+"/oauth/token", v, "", "")
	if r2.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("second redemption: %d %v", r2.StatusCode, body)
	}
	if r, _ := e.mcp(e.public, tok["access_token"].(string), list); r.StatusCode != 401 {
		t.Fatalf("session of a reused code still served: %d", r.StatusCode)
	}
	e.WaitEvent(func(ev audit.Event) bool { return ev.ReasonCode == "AUTH_CODE_REUSE" && ev.ClientID == id })
}

// Session Approver password guesses spread over several approved clients
// and source addresses still lock the username, after twice the client
// threshold of failures.
func TestRemoteApproverLockoutAcrossClients(t *testing.T) {
	e := newEnv(t, "[remote.limits]\nlockout_failures = 2\nlockout = \"1m\"\n")
	e.enable()
	redirect := "http://127.0.0.1/callback"
	var clients []string
	for i := range 5 {
		callerAddr.Store(fmt.Sprintf("198.51.100.%d", 10+i))
		id := e.register(redirect)["client_id"].(string)
		if st, body := e.Admin("POST", "/api/v1/clients/"+id+"/approve", map[string]any{}); st != 200 {
			t.Fatalf("approve %d %v", st, body)
		}
		clients = append(clients, id)
	}
	_, challenge := pkce()
	attempt := func(i int, client, password string) int {
		callerAddr.Store(fmt.Sprintf("203.0.113.%d", 20+i))
		q := authorizeQuery(client, redirect, challenge, "smcp:template:remote", e.public+"/mcp")
		q.Set("username", gwtest.ApproverUser)
		q.Set("password", password)
		resp, _ := e.postForm(e.public+"/oauth/authorize", q, "", "")
		return resp.StatusCode
	}
	// One failure per client and per source: no client or source reaches
	// its threshold of 2.
	for i := range 4 {
		if st := attempt(i, clients[i], "wrong password"); st != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, st)
		}
	}
	if st := attempt(9, clients[4], gwtest.ApproverPassword); st != http.StatusTooManyRequests {
		t.Fatalf("right password after 4 spread failures: %d, want 429", st)
	}
	e.WaitEvent(func(ev audit.Event) bool { return ev.ReasonCode == "REMOTE_APPROVER_LOCKOUT" && ev.Channel == "remote" })
}

// RR-02: one caller address can hold at most max_pending_per_source
// pending registrations (an IPv6 address counts as its /64), so it cannot
// take the whole pending queue; other addresses can still register. A
// refused registration writes no evidence.
func TestRegistrationPerSourceQuota(t *testing.T) {
	e := newEnv(t, "max_pending_per_source = 2\n")
	e.enable()
	post := func() (*http.Response, []byte) {
		b, _ := json.Marshal(map[string]any{"redirect_uris": []string{"http://127.0.0.1/callback"}, "token_endpoint_auth_method": "none"})
		req, _ := http.NewRequest("POST", e.public+"/oauth/register", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		return e.do(req)
	}
	count := func() int {
		n := 0
		for _, ev := range e.Events() {
			if ev.Class == "client_registration" {
				n++
			}
		}
		return n
	}
	for i, addr := range []string{"2001:db8:1:2::10", "2001:db8:1:2::11"} {
		callerAddr.Store(addr)
		if resp, raw := post(); resp.StatusCode != http.StatusCreated {
			t.Fatalf("registration %d: %d %s", i, resp.StatusCode, raw)
		}
	}
	e.WaitEvent(func(audit.Event) bool { return count() == 2 })
	callerAddr.Store("2001:db8:1:2::99") // same /64
	resp, raw := post()
	if resp.StatusCode != http.StatusTooManyRequests || !bytes.Contains(raw, []byte("from this address")) {
		t.Fatalf("third registration from one /64: %d %s", resp.StatusCode, raw)
	}
	callerAddr.Store("198.51.100.40")
	if resp, raw := post(); resp.StatusCode != http.StatusCreated {
		t.Fatalf("registration from another address: %d %s", resp.StatusCode, raw)
	}
	e.WaitEvent(func(audit.Event) bool { return count() == 3 })
	if n := count(); n != 3 {
		t.Fatalf("%d client_registration events, want 3", n)
	}
}
