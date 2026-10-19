package egress

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var testBinding = pipeline.Binding{CorrelationID: "corr-1", DecisionID: "dec-1", PolicyRevision: "rev-1", PublicName: "web_fetch"}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func requireCaps(o *Options) { o.RequireCapability = true; o.CapabilityTokens = 3 }

// get sends one plain-HTTP proxy request with the capability tok ("" for
// none).
func capGet(t *testing.T, att *pipeline.EgressAttachment, target, tok string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", target, nil)
	if tok != "" {
		req.Header.Set(AuthHeader, tok)
	}
	resp, err := proxyClient(att, nil, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// connectStatus sends CONNECT host:port with the capability tok and
// returns the status line.
func connectStatus(t *testing.T, att *pipeline.EgressAttachment, hostport, tok string) string {
	t.Helper()
	pc, err := net.Dial("tcp", strings.TrimPrefix(att.Env["HTTP_PROXY"], "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	hdr := ""
	if tok != "" {
		hdr = AuthHeader + ": " + tok + "\r\n"
	}
	fmt.Fprintf(pc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", hostport, hostport, hdr)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(pc).ReadString('\n')
	return strings.TrimSpace(line)
}

// TestEgressCapabilities is SR-5.16-1 against the broker: with
// capabilities required, every operation (plain-HTTP proxy request,
// CONNECT tunnel and endpoint request) is forwarded only with an unused
// token minted for the current call to this instance and for the grant of
// the destination; the token's call (correlation ID, decision ID, policy
// revision) is recorded; a missing, replayed, revoked, expired, foreign
// or other-destination token is refused and recorded as a denial before
// any connection; and the header never reaches the destination.
func TestEgressCapabilities(t *testing.T) {
	reqtest.Verifies(t, "SR-5.16-1")
	var mu sync.Mutex
	var seenAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenAuth = append(seenAuth, r.Header.Get(AuthHeader))
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenAuth = append(seenAuth, r.Header.Get(AuthHeader))
		mu.Unlock()
		io.WriteString(w, "tls-ok")
	}))
	defer tlsSrv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	port, tport := portOfURL(t, srv.URL), portOfURL(t, tlsSrv.URL)
	clk := &clock{t: time.Now()} // tunnel deadlines use the clock
	h := newHarness(t, []Grant{
		{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET", MethodConnect}, Addresses: loopback},
		{Server: "web", Host: "other.test", Ports: []int{port}, Methods: []string{"GET"}, Addresses: loopback},
		{Server: "web", Host: "example.com", Ports: []int{tport}, Methods: []string{"GET"}, Addresses: loopback, EndpointEnv: "API_URL"},
	}, Limits{}, requireCaps, func(o *Options) { o.RootCAs = pool; o.Now = clk.now })
	for _, n := range []string{"api.test", "other.test", "example.com"} {
		h.res.answers[n] = [][]string{{"127.0.0.1"}}
	}
	att := h.attach()
	if att.Issue == nil {
		t.Fatal("attachment does not mint capabilities")
	}
	auth, revoke := att.Issue(testBinding)
	if auth.Header != AuthHeader || len(auth.Destinations) != 3 || len(auth.Destinations[0].Tokens) != 3 ||
		auth.Destinations[2].Endpoint != "API_URL" || !auth.ExpiresAt.Equal(clk.now().Add(CapabilityTTL)) {
		t.Fatalf("auth %+v", auth)
	}
	api := fmt.Sprintf("http://api.test:%d/x", port)
	other := fmt.Sprintf("http://other.test:%d/x", port)

	type step struct {
		name, reason, capState string
		do                     func() int // returns the HTTP status (or 200 for an established tunnel)
	}
	var (
		apiTok   = auth.Take("api.test", port)
		otherTok = auth.Take("other.test", port)
	)
	steps := []step{
		{"no capability", ReasonCapabilityRequired, CapabilityMissing, func() int { return capGet(t, att, api, "").StatusCode }},
		{"valid", "", CapabilityConsumed, func() int { return capGet(t, att, api, apiTok).StatusCode }},
		{"replay", ReasonCapabilityReplayed, CapabilityReplayed, func() int { return capGet(t, att, api, apiTok).StatusCode }},
		{"other destination", ReasonCapabilityMismatch, CapabilityMismatch, func() int { return capGet(t, att, api, otherTok).StatusCode }},
		{"spent by the mismatch", ReasonCapabilityReplayed, CapabilityReplayed, func() int { return capGet(t, att, other, otherTok).StatusCode }},
		{"forged", ReasonCapabilityInvalid, CapabilityInvalid, func() int { return capGet(t, att, api, "smcpe_forged").StatusCode }},
		{"connect without", ReasonCapabilityRequired, CapabilityMissing, func() int {
			if s := connectStatus(t, att, fmt.Sprintf("api.test:%d", port), ""); !strings.Contains(s, "403") {
				t.Fatalf("CONNECT without capability: %q", s)
			}
			return 403
		}},
		{"connect with", "", CapabilityConsumed, func() int {
			if s := connectStatus(t, att, fmt.Sprintf("api.test:%d", port), auth.Take("api.test", port)); !strings.Contains(s, "200") {
				t.Fatalf("CONNECT with capability: %q", s)
			}
			return 200
		}},
		{"endpoint without", ReasonCapabilityRequired, CapabilityMissing, func() int {
			resp, err := http.Get(att.Env["API_URL"] + "/e")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp.StatusCode
		}},
		{"endpoint with", "", CapabilityConsumed, func() int {
			req, _ := http.NewRequest("GET", att.Env["API_URL"]+"/e", nil)
			req.Header.Set(AuthHeader, auth.Take("example.com", tport))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "tls-ok" {
				t.Fatalf("endpoint body %q", b)
			}
			return resp.StatusCode
		}},
	}
	for i, s := range steps {
		st := s.do()
		recs := waitRecords(t, h.b, i+1)
		var rec Record
		if s.name == "connect with" {
			// The tunnel record is written when the tunnel ends; find it.
			for range 200 {
				if recs = h.b.Recent(); len(recs) > i && recs[0].Capability == CapabilityConsumed && recs[0].Mode == ModeConnect {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		rec = recs[0]
		wantStatus := 200
		if s.reason != "" {
			wantStatus = http.StatusForbidden
		}
		if st != wantStatus || rec.Capability != s.capState {
			t.Fatalf("%s: status %d, record %+v", s.name, st, rec)
		}
		if s.reason != "" && (rec.Reason != s.reason || rec.Decision != DecisionDenied) {
			t.Fatalf("%s: record %+v", s.name, rec)
		}
		known := s.capState != CapabilityMissing && s.capState != CapabilityInvalid
		if known && (rec.CorrelationID != "corr-1" || rec.DecisionID != "dec-1" || rec.PolicyRevision != "rev-1") {
			t.Fatalf("%s: record lacks the call binding: %+v", s.name, rec)
		}
	}
	// Refusals happen before any connection: only the three forwarded
	// operations dialed (proxy GET, CONNECT, endpoint).
	if d := h.dials(); len(d) != 3 {
		t.Fatalf("dials %v", d)
	}
	mu.Lock()
	for _, a := range seenAuth {
		if a != "" {
			t.Fatalf("destination received %s: %q", AuthHeader, a)
		}
	}
	if len(seenAuth) != 2 {
		t.Fatalf("destination requests %d", len(seenAuth))
	}
	mu.Unlock()
	// Evidence: the authorized event names the call.
	found := false
	for _, ev := range h.ev.Events() {
		if ev.Class == "egress" && ev.Phase == audit.PhaseAuthorized && ev.CorrelationID == "corr-1" && ev.DecisionID == "dec-1" && ev.PolicyRevision == "rev-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("no authorized event carries the call's binding")
	}

	// Revocation at the end of the call: the remaining tokens are refused.
	left := auth.Take("api.test", port)
	revoke()
	revoke() // idempotent
	if h.b.outstanding() != 0 {
		t.Fatalf("%d tokens outstanding after revoke", h.b.outstanding())
	}
	if r := capGet(t, att, api, left); reasonOf(r) != ReasonCapabilityInvalid {
		t.Fatalf("revoked token: %d %s", r.StatusCode, reasonOf(r))
	}

	// Expiry of a call that never returns.
	auth2, revoke2 := att.Issue(testBinding)
	defer revoke2()
	clk.add(CapabilityTTL + time.Second)
	if r := capGet(t, att, api, auth2.Take("api.test", port)); reasonOf(r) != ReasonCapabilityInvalid {
		t.Fatalf("expired token: %d %s", r.StatusCode, reasonOf(r))
	}

	// A token of another instance of the same server is refused.
	att2 := h.attach()
	auth3, revoke3 := att2.Issue(testBinding)
	defer revoke3()
	if r := capGet(t, att, api, auth3.Take("api.test", port)); reasonOf(r) != ReasonCapabilityMismatch {
		t.Fatalf("foreign instance token: %d %s", r.StatusCode, reasonOf(r))
	}
}

// TestEgressCapabilitiesOptional: without RequireCapability the broker
// mints nothing (Issue only records the call's egress-limit obligation,
// bounds.go) and still removes the header.
func TestEgressCapabilitiesOptional(t *testing.T) {
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{443}, Methods: []string{"GET"}}}, Limits{})
	auth, end := h.attach().Issue(testBinding)
	defer end()
	if auth != nil || h.b.outstanding() != 0 {
		t.Fatalf("capabilities minted although not required: %+v", auth)
	}
}

// TestLaunchedProcessIssues: a wrapped launch exposes the broker's issuer
// through the process, also behind further wrappers, and a server without
// grants receives no capabilities.
func TestLaunchedProcessIssues(t *testing.T) {
	reqtest.Partial(t, "SR-5.16-1")
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{443}, Methods: []string{"GET"}}}, Limits{}, requireCaps)
	l := h.b.Wrap(&captureLauncher{})
	p, err := l.Launch(context.Background(), pipeline.ServerSpec{Alias: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	is := pipeline.EgressIssuerOf(wrapped{p})
	if is == nil {
		t.Fatal("no issuer behind the wrapper")
	}
	auth, revoke := is.IssueEgress(testBinding)
	if auth == nil || len(auth.Destinations) != 1 || len(auth.Destinations[0].Tokens) != 3 {
		t.Fatalf("auth %+v", auth)
	}
	revoke()
	p2, err := l.Launch(context.Background(), pipeline.ServerSpec{Alias: "nogrants"})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	if a, _ := pipeline.EgressIssuerOf(p2).IssueEgress(testBinding); a != nil {
		t.Fatalf("server without grants got %+v", a)
	}
}

type wrapped struct{ pipeline.Process }

func (w wrapped) Unwrap() pipeline.Process { return w.Process }
