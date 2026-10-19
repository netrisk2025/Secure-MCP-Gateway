package egress

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestLimitSources is FR-5.38 against the broker: each outbound
// operation's request size, response size and duration are bounded by the
// smallest of the Runtime Profile (configuration and grant), the manifest
// and the decision obligation carried by the call's capability. For each
// source in turn that source holds the smallest bounds while the other two
// are larger; a fixture exceeds each bound, and the operation is
// terminated with the reason code and an evidence event. A small request
// succeeds and its record carries the bounds applied. The sources reach
// the broker as tested in TestEgressLimitObligationEndToEnd (internal/e2e:
// policy rule to decision to capability), TestManifestEgressLimits
// (internal/library) and TestManifestLimitsAdapter (internal/app).
func TestLimitSources(t *testing.T) {
	reqtest.Verifies(t, "FR-5.38")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Length", strconv.Itoa(4096))
			w.Write(make([]byte, 4096))
		case "/big-stream":
			for range 4 {
				w.Write(make([]byte, 1024))
				w.(http.Flusher).Flush()
			}
		case "/slow":
			time.Sleep(900 * time.Millisecond)
			io.WriteString(w, "late")
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	small := struct {
		req, resp int64
		timeout   time.Duration
	}{1000, 2000, 300 * time.Millisecond}
	const largeReq, largeResp, largeTimeout = 5000, 8000, 5 * time.Second
	base := fmt.Sprintf("http://api.test:%d", port)

	for _, source := range []string{"runtime-profile", "manifest", "obligation"} {
		t.Run(source, func(t *testing.T) {
			grant := Grant{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET", "POST"}, Addresses: loopback,
				RequestBytes: largeReq, ResponseBytes: largeResp, Timeout: largeTimeout}
			ml := ManifestLimit{Host: "*.test", Ports: []int{port}, RequestBytes: largeReq, ResponseBytes: largeResp, Timeout: largeTimeout}
			ob := pipeline.EgressLimits{RequestBytes: largeReq, ResponseBytes: largeResp, Timeout: largeTimeout}
			switch source {
			case "runtime-profile":
				grant.RequestBytes, grant.ResponseBytes, grant.Timeout = small.req, small.resp, small.timeout
			case "manifest":
				ml.RequestBytes, ml.ResponseBytes, ml.Timeout = small.req, small.resp, small.timeout
			case "obligation":
				ob = pipeline.EgressLimits{RequestBytes: small.req, ResponseBytes: small.resp, Timeout: small.timeout}
			}
			h := newHarness(t, []Grant{grant}, Limits{RequestBytes: 1 << 20, ResponseBytes: 8 << 20, OperationTimeout: time.Minute, RequestsPerMinute: 1000},
				func(o *Options) { o.RequireCapability, o.CapabilityTokens = true, 16 })
			h.b.SetManifestLimits(func(server string) []ManifestLimit {
				if server != "web" {
					return nil
				}
				// A rule for another destination never applies.
				return []ManifestLimit{ml, {Host: "other.example", Ports: []int{port}, RequestBytes: 1, ResponseBytes: 1, Timeout: time.Millisecond}}
			})
			h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
			att := h.attach()
			bnd := testBinding
			bnd.Egress = ob
			auth, revoke := att.Issue(bnd)
			defer revoke()
			c := proxyClient(att, nil, "")
			do := func(method, path string, body io.Reader) (*http.Response, error) {
				req, _ := http.NewRequest(method, base+path, body)
				req.Header.Set(AuthHeader, auth.Take("api.test", port))
				resp, err := c.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				return resp, err
			}
			if r, err := do("GET", "/", nil); err != nil || r.StatusCode != 200 {
				t.Fatalf("small request: %v %v", r, err)
			}
			rec := waitRecords(t, h.b, 1)[0]
			want := Bounds{RequestBytes: small.req, ResponseBytes: small.resp, TimeoutMS: small.timeout.Milliseconds()}
			if rec.Bounds == nil || *rec.Bounds != want || rec.DecisionID != testBinding.DecisionID {
				t.Fatalf("record bounds %+v, want %+v (record %+v)", rec.Bounds, want, rec)
			}
			// Request size: declared and streamed bodies above 1000 bytes.
			if r, _ := do("POST", "/", strings.NewReader(strings.Repeat("x", 1500))); r == nil || reasonOf(r) != ReasonRequestTooLarge {
				t.Fatalf("declared request size: %v", r)
			}
			if r, _ := do("POST", "/", io.MultiReader(strings.NewReader(strings.Repeat("y", 1500)))); r == nil || reasonOf(r) != ReasonRequestTooLarge {
				t.Fatalf("streamed request size: %v", r)
			}
			// Response size: declared and streamed bodies above 2000 bytes.
			if r, _ := do("GET", "/big", nil); r == nil || reasonOf(r) != ReasonResponseTooLarge {
				t.Fatalf("declared response size: %v", r)
			}
			_, _ = do("GET", "/big-stream", nil)
			if rec := waitRecords(t, h.b, 5)[0]; rec.Reason != ReasonResponseTooLarge {
				t.Fatalf("streamed response record %+v", rec)
			}
			// Duration: the destination answers after 900 ms.
			start := time.Now()
			if r, _ := do("GET", "/slow", nil); r == nil || reasonOf(r) != ReasonTimeout {
				t.Fatalf("duration: %v", r)
			}
			if d := time.Since(start); d > 800*time.Millisecond {
				t.Fatalf("the duration bound took %v", d)
			}
			// Every termination has an evidence event with its reason.
			rs := waitRecords(t, h.b, 6)
			terminated := 0
			for _, r := range rs {
				if r.Reason == "" {
					continue
				}
				terminated++
				found := false
				for _, ev := range h.ev.Events() {
					if d, ok := ev.Detail.(Record); ok && d.ID == r.ID && ev.ReasonCode == r.Reason {
						found = true
					}
				}
				if !found {
					t.Fatalf("no event for %+v", r)
				}
			}
			if terminated != 5 {
				t.Fatalf("%d terminated operations, want 5: %+v", terminated, rs)
			}
		})
	}
}

// TestLimitSourcesTunnel: a CONNECT tunnel's duration is bounded by the
// call's obligation too.
func TestLimitSourcesTunnel(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	h := newHarness(t, []Grant{{Server: "web", Host: "tunnel.test", Ports: []int{443}, Methods: []string{MethodConnect}, Addresses: loopback}},
		Limits{}, func(o *Options) { o.RequireCapability, o.CapabilityTokens = true, 2 })
	att := h.attach()
	bnd := testBinding
	bnd.Egress = pipeline.EgressLimits{Timeout: 250 * time.Millisecond, RequestBytes: 4096}
	auth, revoke := att.Issue(bnd)
	defer revoke()
	h.res.answers["tunnel.test"] = [][]string{{"127.0.0.1"}}
	// No listener on 443 is needed: the bounds are fixed when the tunnel
	// is authorized, before the dial.
	_ = connectStatus(t, att, "tunnel.test:443", auth.Take("tunnel.test", 443))
	rec := waitRecords(t, h.b, 1)[0]
	if rec.Bounds == nil || rec.Bounds.TimeoutMS != 250 || rec.Bounds.RequestBytes != 4096 || rec.Bounds.ResponseBytes != 8<<20 {
		t.Fatalf("tunnel record %+v", rec)
	}
}

// TestObligationWithoutCapabilities: with capabilities not required an
// operation is not bound to one call, so the tightest obligation, per
// bound, of the calls the instance is serving applies; when those calls
// end, the configuration's bounds apply again.
func TestObligationWithoutCapabilities(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Write(make([]byte, 3000))
	}))
	defer srv.Close()
	port := portOfURL(t, srv.URL)
	h := newHarness(t, []Grant{{Server: "web", Host: "api.test", Ports: []int{port}, Methods: []string{"GET", "POST"}, Addresses: loopback}},
		Limits{RequestsPerMinute: 1000})
	h.res.answers["api.test"] = [][]string{{"127.0.0.1"}}
	att := h.attach()
	c := proxyClient(att, nil, "")
	get := func(body int) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("POST", fmt.Sprintf("http://api.test:%d/", port), strings.NewReader(strings.Repeat("x", body)))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	b1, b2 := testBinding, testBinding
	b1.Egress = pipeline.EgressLimits{RequestBytes: 1000, Timeout: 2 * time.Second}
	b2.Egress = pipeline.EgressLimits{RequestBytes: 4000, ResponseBytes: 2000}
	_, end1 := att.Issue(b1)
	_, end2 := att.Issue(b2)
	if r := get(1500); reasonOf(r) != ReasonRequestTooLarge {
		t.Fatalf("request above the tightest obligation: %d %s", r.StatusCode, reasonOf(r))
	}
	if rec := waitRecords(t, h.b, 1)[0]; rec.Bounds == nil || *rec.Bounds != (Bounds{RequestBytes: 1000, ResponseBytes: 2000, TimeoutMS: 2000}) {
		t.Fatalf("combined bounds %+v", rec.Bounds)
	}
	end1()
	end1() // idempotent
	// The 3000-byte answer is cut after its headers (the connection is
	// aborted); the record has the reason.
	_ = get(1500)
	if rec := waitRecords(t, h.b, 2)[0]; rec.Reason != ReasonResponseTooLarge || rec.Bounds.ResponseBytes != 2000 {
		t.Fatalf("response above the remaining obligation: %+v", rec)
	}
	end2()
	if r := get(1500); r.StatusCode != 200 {
		t.Fatalf("after the calls ended: %d %s", r.StatusCode, reasonOf(r))
	}
	if rec := waitRecords(t, h.b, 3)[0]; rec.Bounds == nil || *rec.Bounds != (Bounds{RequestBytes: 1 << 20, ResponseBytes: 8 << 20, TimeoutMS: 30000}) {
		t.Fatalf("configuration bounds %+v", rec.Bounds)
	}
}

// TestManifestCovers matches manifest hosts as the library's egress
// ceiling does: exact names and "*.suffix" subdomains.
func TestManifestCovers(t *testing.T) {
	for _, c := range []struct {
		rule, host string
		want       bool
	}{
		{"api.test", "api.test", true}, {"API.test.", "api.test", true}, {"*.test", "api.test", true},
		{"*.test", "test", false}, {"*.test", "a.b.test", true}, {"api.test", "b.api.test", false},
	} {
		if got := manifestCovers(c.rule, c.host); got != c.want {
			t.Errorf("manifestCovers(%q, %q) = %v", c.rule, c.host, got)
		}
	}
}
